// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"ctlplne.dev/cratectl/internal/debian"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) debianRelease(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	switch r.Method {
	case http.MethodPut:
		if i.Role != "admin" {
			respondErr(w, store.ErrDenied)
			return
		}
		s.publishDebianRelease(w, r, i, repo)
	case http.MethodGet, http.MethodHead:
		a, err := s.DB.DebianRelease(ctx, i, repo.Name, s.NativeVersionLimit, s.NativeMetadataBytes)
		if err != nil {
			respondErr(w, err)
			return
		}
		file, err := s.Blobs.OpenVerified(ctx, i.Tenant, a.Digest, a.Size)
		if err != nil {
			respondErr(w, err)
			return
		}
		defer file.Close()
		current, err := s.DB.DebianRelease(ctx, i, repo.Name, s.NativeVersionLimit, s.NativeMetadataBytes)
		if err != nil {
			respondErr(w, err)
			return
		}
		if current.Digest != a.Digest {
			respondErr(w, store.ErrConflict)
			return
		}
		w.Header().Set("Content-Type", a.MediaType)
		w.Header().Set("ETag", `"sha256:`+a.Digest+`"`)
		http.ServeContent(w, r, "InRelease", a.Created, file)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		fail(w, 405, "method_not_allowed", "Publish an externally signed Debian InRelease with PUT or consume it with GET or HEAD.")
	}
}

func (s *Server) publishDebianRelease(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, debian.MaxReleaseBytes))
	if err != nil {
		fail(w, 413, "debian_release_budget", "Supply an InRelease within the metadata upload limit.")
		return
	}
	distribution := repo.Settings.DebianDistribution
	release, err := debian.ParseInRelease(raw, distribution)
	if err != nil {
		fail(w, 400, "invalid_debian_release", "Supply an externally clear-signed InRelease with Date, Valid-Until and exact SHA-256 entries for the configured indexes.")
		return
	}
	metadata, err := json.Marshal(release)
	if err != nil {
		respondErr(w, err)
		return
	}
	ctx := r.Context()
	object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(raw), "", int64(len(raw)))
	if err != nil {
		respondErr(w, err)
		return
	}
	if err = s.DB.PublishDebianRelease(ctx, i, repo.Name, store.Artifact{Path: distribution.ReleasePath(), Digest: object.Digest, Size: object.Size,
		MediaType: store.DebianReleaseMedia, Metadata: metadata}, s.NativeVersionLimit, s.NativeMetadataBytes); err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("X-Checksum-Sha256", object.Digest)
	w.WriteHeader(http.StatusCreated)
}
