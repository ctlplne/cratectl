// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/debian"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) apt(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, path string) {
	path = strings.TrimPrefix(path, "./")
	if path == store.DebianReleasePath {
		s.debianRelease(w, r, i, repo.Name)
		return
	}
	if path == "Packages" || path == "Packages.gz" || strings.HasPrefix(path, "by-hash/SHA256/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, 405, "method_not_allowed", "Read the derived Debian Packages index with GET or HEAD.")
			return
		}
		s.serveDebianPackages(w, r, i, repo.Name, path)
		return
	}
	if !debian.ValidPoolPath(path) {
		respondErr(w, store.ErrNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	switch r.Method {
	case http.MethodPut:
		s.publishDebian(w, r, i, repo.Name, path)
	case http.MethodGet, http.MethodHead:
		resolved, err := s.resolve(ctx, i, repo, path, false)
		if err != nil {
			respondErr(w, err)
			return
		}
		s.serveResolvedArtifact(w, r, i, resolved)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		fail(w, 405, "method_not_allowed", "Publish a Debian package with PUT or consume it with GET or HEAD.")
	}
}

func (s *Server) publishDebian(w http.ResponseWriter, r *http.Request, i store.Identity, repo, path string) {
	if r.ContentLength > debian.MaxArchiveBytes {
		fail(w, 413, "debian_archive_budget", "Reduce the Debian archive within the upload limit.")
		return
	}
	object, err := s.Blobs.Put(r.Context(), i.Tenant, http.MaxBytesReader(w, r.Body, debian.MaxArchiveBytes), "", r.ContentLength)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(w, 413, "debian_archive_budget", "Reduce the Debian archive within the upload limit.")
			return
		}
		respondErr(w, err)
		return
	}
	file, err := s.Blobs.OpenVerified(r.Context(), i.Tenant, object.Digest, object.Size)
	if err != nil {
		respondErr(w, err)
		return
	}
	control, err := debian.Inspect(r.Context(), file, object.Size)
	file.Close()
	if errors.Is(err, debian.ErrArchive) || errors.Is(err, debian.ErrControl) {
		fail(w, 400, "invalid_debian_archive", "Use a bounded Debian 2.0 binary archive with a plain or gzip control member.")
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	if control.PoolPath() != path {
		fail(w, 409, "debian_coordinate_mismatch", "Publish to the pool path matching the package, version and architecture in its control stanza.")
		return
	}
	metadata, err := json.Marshal(store.DebianPackage{Control: []byte(control.Stanza), Validated: true})
	if err != nil {
		respondErr(w, err)
		return
	}
	if err := s.DB.PublishDebian(r.Context(), i, repo, store.Artifact{Path: path, Digest: object.Digest, Size: object.Size,
		MediaType: store.DebianMedia, Metadata: metadata}); err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("X-Checksum-Sha256", object.Digest)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) serveDebianPackages(w http.ResponseWriter, r *http.Request, i store.Identity, repo, path string) {
	index, err := s.DB.DebianPackageIndex(r.Context(), i, repo, s.NativeVersionLimit, s.NativeMetadataBytes)
	if err != nil {
		respondErr(w, err)
		return
	}
	media := "text/plain; charset=utf-8"
	requestedHash, byHash := strings.CutPrefix(path, "by-hash/SHA256/")
	if path == "Packages.gz" || (byHash && crypt.Digest(index) != requestedHash) {
		compressed, err := debian.GzipIndex(index)
		if err != nil {
			respondErr(w, err)
			return
		}
		if int64(len(compressed)) > s.NativeMetadataBytes {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
		index, media = compressed, "application/gzip"
	}
	digest := crypt.Digest(index)
	if byHash && requestedHash != digest {
		respondErr(w, store.ErrNotFound)
		return
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("ETag", `"sha256:`+digest+`"`)
	http.ServeContent(w, r, path, time.Time{}, bytes.NewReader(index))
}
