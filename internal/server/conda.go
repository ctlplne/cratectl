// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/conda"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) conda(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, request string) {
	if subdir, name, found := strings.Cut(request, "/"); found && conda.ValidSubdir(subdir) &&
		(name == "repodata.json" || name == "current_repodata.json") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, 405, "method_not_allowed", "Read Conda channel metadata with GET or HEAD.")
			return
		}
		var index string
		var err error
		if repo.Mode == "group" {
			channel := s.PublicURL + "/conda/" + repo.Name + "/"
			index, err = s.DB.CondaGroupRepodata(r.Context(), i, repo.Name, subdir, channel, repo.SourceRevision, s.NativeVersionLimit, s.NativeMetadataBytes)
		} else {
			index, err = s.DB.CondaRepodata(r.Context(), i, repo.Name, subdir, s.NativeVersionLimit, s.NativeMetadataBytes)
		}
		if err != nil {
			respondErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.Header().Set("ETag", `"sha256:`+crypt.Digest([]byte(index))+`"`)
		http.ServeContent(w, r, name, time.Time{}, strings.NewReader(index))
		return
	}
	if repo.Mode == "group" {
		s.serveCondaGroupPackage(w, r, i, repo, request)
		return
	}
	coordinate, ok := conda.ParsePath(request)
	if !ok {
		respondErr(w, store.ErrNotFound)
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.publishConda(w, r, i, repo.Name, coordinate)
	case http.MethodGet, http.MethodHead:
		resolved, err := s.resolve(r.Context(), i, repo, request, false)
		if err == nil {
			_, err = store.ValidateCondaArtifact(resolved.artifact)
		}
		if err != nil {
			respondErr(w, err)
			return
		}
		s.serveResolvedArtifact(w, r, i, resolved)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		fail(w, 405, "method_not_allowed", "Publish a Conda tar.bz2 package with PUT or consume it with GET or HEAD.")
	}
}

func (s *Server) serveCondaGroupPackage(w http.ResponseWriter, r *http.Request, i store.Identity, group store.Repository, request string) {
	subdir, rest, ok := strings.Cut(request, "/snapshot/")
	digest, file, found := strings.Cut(rest, "/")
	if !ok || !found || len(digest) != 64 {
		respondErr(w, store.ErrNotFound)
		return
	}
	artifact, source, err := s.DB.CondaGroupArtifact(r.Context(), i, group.Name, subdir+"/"+file, digest, group.SourceRevision, s.NativeVersionLimit)
	if err != nil {
		respondErr(w, err)
		return
	}
	s.serveResolvedArtifact(w, r, i, resolvedArtifact{artifact: artifact, source: source, groups: []string{group.Name},
		groupRevisions: map[string]int64{group.Name: group.SourceRevision}, condaGroupView: digest})
}

func (s *Server) publishConda(w http.ResponseWriter, r *http.Request, i store.Identity, repo string, coordinate conda.Coordinate) {
	if r.ContentLength > conda.MaxArchiveBytes {
		fail(w, 413, "conda_archive_budget", "Reduce the Conda tar.bz2 archive within the upload limit.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	checksum := crypt.CompatibilityHash("md5")
	body := io.TeeReader(http.MaxBytesReader(w, r.Body, conda.MaxArchiveBytes), checksum)
	object, err := s.Blobs.Put(ctx, i.Tenant, body, "", r.ContentLength)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(w, 413, "conda_archive_budget", "Reduce the Conda tar.bz2 archive within the upload limit.")
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
	metadata, err := conda.Inspect(ctx, file, object.Size, coordinate)
	file.Close()
	if errors.Is(err, conda.ErrPackage) {
		fail(w, 400, "invalid_conda_archive", "Supply a bounded Conda tar.bz2 package whose info/index.json matches the requested subdirectory and filename.")
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	encoded, err := json.Marshal(store.CondaPackage{Package: metadata, MD5: hex.EncodeToString(checksum.Sum(nil)), Validated: true})
	if err != nil {
		respondErr(w, err)
		return
	}
	if err := s.DB.PublishConda(ctx, i, repo, store.Artifact{
		Path: coordinate.Path(), Digest: object.Digest, Size: object.Size, MediaType: store.CondaMedia, Metadata: encoded,
	}); err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("X-Checksum-Sha256", object.Digest)
	w.WriteHeader(http.StatusCreated)
}
