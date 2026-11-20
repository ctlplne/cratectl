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
	if repo.Mode == "group" {
		s.serveCondaGroup(w, r, i, repo, request)
		return
	}
	if subdir, name, found := strings.Cut(request, "/"); found && conda.ValidSubdir(subdir) &&
		(name == "repodata.json" || name == "current_repodata.json") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, 405, "method_not_allowed", "Read Conda channel metadata with GET or HEAD.")
			return
		}
		index, err := s.DB.CondaRepodata(r.Context(), i, repo.Name, subdir, s.NativeVersionLimit, s.NativeMetadataBytes)
		serveCondaIndex(w, r, name, index, err)
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
		fail(w, 405, "method_not_allowed", "Publish a Conda package with PUT or consume it with GET or HEAD.")
	}
}

func serveCondaIndex(w http.ResponseWriter, r *http.Request, name, index string, err error) {
	if err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest([]byte(index))+`"`)
	http.ServeContent(w, r, name, time.Time{}, strings.NewReader(index))
}

func (s *Server) serveCondaGroup(w http.ResponseWriter, r *http.Request, i store.Identity, group store.Repository, request string) {
	channel := s.PublicURL + "/conda/" + group.Name + "/"
	ctx := r.Context()
	if request == "snapshot.json" {
		digest, err := s.DB.CondaGroupChannelSnapshot(ctx, i, group.Name, group.SourceRevision, s.NativeVersionLimit)
		if err != nil {
			respondErr(w, err)
			return
		}
		w.Header().Set("Cache-Control", "private, no-cache")
		writeJSON(w, 200, map[string]string{"channel": channel + "snapshots/" + digest + "/", "sha256": digest})
		return
	}
	var snapshot store.CondaSnapshot
	if rest, pinned := strings.CutPrefix(request, "snapshots/"); pinned {
		var found bool
		snapshot.Digest, request, found = strings.Cut(rest, "/")
		if !found || len(snapshot.Digest) != 64 {
			respondErr(w, store.ErrNotFound)
			return
		}
		snapshot.EntireChannel = true
	}
	subdir, name, found := strings.Cut(request, "/")
	if !found || !conda.ValidSubdir(subdir) {
		respondErr(w, store.ErrNotFound)
		return
	}
	if name == "repodata.json" || name == "current_repodata.json" {
		index, err := s.DB.CondaGroupRepodata(ctx, i, group.Name, subdir, channel, snapshot.Digest, group.SourceRevision, s.NativeVersionLimit, s.NativeMetadataBytes)
		serveCondaIndex(w, r, name, index, err)
		return
	}
	if !snapshot.EntireChannel {
		rest, pinned := strings.CutPrefix(name, "snapshot/")
		snapshot.Digest, name, found = strings.Cut(rest, "/")
		if !pinned || !found || len(snapshot.Digest) != 64 {
			respondErr(w, store.ErrNotFound)
			return
		}
	}
	artifact, source, err := s.DB.CondaGroupArtifact(ctx, i, group.Name, subdir+"/"+name, snapshot, group.SourceRevision, s.NativeVersionLimit)
	if err != nil {
		respondErr(w, err)
		return
	}
	s.serveResolvedArtifact(w, r, i, resolvedArtifact{artifact: artifact, source: source, groups: []string{group.Name},
		groupRevisions: map[string]int64{group.Name: group.SourceRevision}, condaGroupView: snapshot})
}

func (s *Server) publishConda(w http.ResponseWriter, r *http.Request, i store.Identity, repo string, coordinate conda.Coordinate) {
	if r.ContentLength > conda.MaxArchiveBytes {
		fail(w, 413, "conda_archive_budget", "Reduce the Conda archive within the upload limit.")
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
			fail(w, 413, "conda_archive_budget", "Reduce the Conda archive within the upload limit.")
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
		fail(w, 400, "invalid_conda_archive", "Supply a bounded .conda or .tar.bz2 archive whose info/index.json matches the requested subdirectory and filename.")
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
		Path: coordinate.Path(), Digest: object.Digest, Size: object.Size, MediaType: coordinate.MediaType(), Metadata: encoded,
	}); err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("X-Checksum-Sha256", object.Digest)
	w.WriteHeader(http.StatusCreated)
}
