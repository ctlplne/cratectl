// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/composer"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

type composerVersion struct {
	composer.Package
	Normalized string       `json:"version_normalized"`
	Dist       composerDist `json:"dist"`
}

type composerDist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	SHA1      string `json:"shasum"`
}

func (s *Server) composer(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, request string) {
	if coordinate, ok := composer.ParseDistribution(request); ok {
		if r.Method == http.MethodPut {
			s.publishComposer(w, r, i, repo.Name, coordinate)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if repo.Mode == "group" {
				s.serveComposerGroup(w, r, i, repo, coordinate)
				return
			}
			s.serveArtifact(w, r, i, repo.Name, coordinate.Path())
			return
		}
		w.Header().Set("Allow", "GET, HEAD, PUT")
		fail(w, 405, "method_not_allowed", "Publish a Composer ZIP with PUT or consume it with GET or HEAD.")
		return
	}

	name, metadata := strings.CutPrefix(request, "p2/")
	name, suffix := strings.CutSuffix(name, ".json")
	name, development := strings.CutSuffix(name, "~dev")
	if request != "packages.json" && !(metadata && suffix && composer.ValidName(name)) {
		respondErr(w, store.ErrNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Read Composer repository metadata with GET or HEAD.")
		return
	}
	base := "/composer/" + repo.Name + "/"
	response := struct {
		Packages    map[string][]composerVersion `json:"packages"`
		MetadataURL string                       `json:"metadata-url,omitempty"`
	}{Packages: map[string][]composerVersion{}}
	if request == "packages.json" {
		response.MetadataURL = base + "p2/%package%.json"
	} else {
		versions, err := s.DB.ComposerVersions(r.Context(), i, repo.Name, name, development, repo.SourceRevision, s.NativeVersionLimit, s.NativeMetadataBytes)
		if err != nil {
			respondErr(w, err)
			return
		}
		rows := make([]composerVersion, 0, len(versions))
		for _, version := range versions {
			p := version.Metadata.Package
			url := s.PublicURL + base + version.Path
			if repo.Mode == "group" {
				url += "?sha256=" + version.Digest
			}
			coordinate := composer.Coordinate{Name: p.Name, Version: p.Version}
			rows = append(rows, composerVersion{Package: p, Normalized: coordinate.NormalizedVersion(), Dist: composerDist{
				Type: "zip", URL: url, Reference: version.Digest, SHA1: version.Metadata.SHA1,
			}})
		}
		response.Packages[name] = rows
	}
	data, err := json.Marshal(response)
	if err != nil {
		respondErr(w, err)
		return
	}
	if int64(len(data)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(data)+`"`)
	http.ServeContent(w, r, request, time.Time{}, bytes.NewReader(data))
}

func (s *Server) serveComposerGroup(w http.ResponseWriter, r *http.Request, i store.Identity, group store.Repository, coordinate composer.Coordinate) {
	digest, ok := strings.CutPrefix(r.URL.RawQuery, "sha256=")
	if !ok || len(digest) != 64 {
		fail(w, 400, "composer_group_digest_required", "Use the group distribution URL advertised in the Composer package metadata.")
		return
	}
	artifact, source, err := s.DB.ComposerGroupArtifact(r.Context(), i, group.Name, coordinate.Path(), digest, group.SourceRevision)
	if errors.Is(err, store.ErrConflict) {
		fail(w, 409, "composer_distribution_changed", "Read current Composer metadata and review the selected distribution before changing the lockfile.")
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	s.serveResolvedArtifact(w, r, i, resolvedArtifact{artifact: artifact, source: source,
		groups: []string{group.Name}, groupRevisions: map[string]int64{group.Name: group.SourceRevision}})
}

func (s *Server) publishComposer(w http.ResponseWriter, r *http.Request, i store.Identity, repo string, coordinate composer.Coordinate) {
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	if r.ContentLength > composer.UploadBytes {
		fail(w, 413, "composer_archive_budget", "Reduce the Composer ZIP within the upload limit.")
		return
	}
	checksum := crypt.CompatibilityHash("sha1")
	body := io.TeeReader(http.MaxBytesReader(w, r.Body, composer.UploadBytes), checksum)
	object, err := s.Blobs.Put(ctx, i.Tenant, body, "", r.ContentLength)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(w, 413, "composer_archive_budget", "Reduce the Composer ZIP within the upload limit.")
			return
		}
		respondErr(w, err)
		return
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		respondErr(w, err)
		return
	}
	packageMetadata, err := composer.Inspect(ctx, file, object.Size, coordinate)
	file.Close()
	if errors.Is(err, composer.ErrPackage) || errors.Is(err, ziparchive.ErrArchive) {
		fail(w, 400, "invalid_composer_archive", "Supply a bounded library ZIP whose composer.json matches the distribution coordinate.")
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	metadata, err := json.Marshal(store.ComposerPackage{Package: packageMetadata, SHA1: hex.EncodeToString(checksum.Sum(nil)), Validated: true})
	if err != nil {
		respondErr(w, err)
		return
	}
	if err = s.DB.PublishComposer(ctx, i, repo, store.Artifact{Path: coordinate.Path(), Digest: object.Digest, Size: object.Size,
		MediaType: store.ComposerMedia, Metadata: metadata}); err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("X-Checksum-Sha256", object.Digest)
	w.WriteHeader(http.StatusCreated)
}
