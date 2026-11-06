// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

type goChecksumFetch struct {
	Proof    store.GoModuleChecksumProof
	Verified crypt.GoSumDBVerification
	Object   blob.Object
}

// readGoModuleChecksumProof admits only the exact retained proof bytes under an
// authorized current repository/cache/policy snapshot. The opaque admission is
// rechecked by common selection after package byte readback, before headers.
// No network, approval or timeline update occurs here.
func (s *Server) readGoModuleChecksumProof(ctx context.Context, i store.Identity, repo store.Repository, c gomodule.Coordinate, admissions ...store.NativeAdmission) (store.NativeAdmission, error) {
	if s.DB == nil || s.Blobs == nil || repo.Format != "go" || repo.Mode != "proxy" {
		return store.NativeAdmission{}, store.ErrGoModuleUnvalidated
	}
	view, err := s.DB.GoModuleChecksumReadback(ctx, i, repo.Name, c, repo.SourceRevision, admissions...)
	if err != nil {
		return store.NativeAdmission{}, err
	}
	object := view.Object()
	if object.Size <= 0 || object.Size > min(s.NativeMetadataBytes, int64(store.MaxGoModuleChecksumProof)) {
		return store.NativeAdmission{}, store.ErrMetadataLimit
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		return store.NativeAdmission{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, object.Size+1))
	if err != nil {
		return store.NativeAdmission{}, err
	}
	marker, err := store.VerifyGoModuleChecksumReadback(ctx, view, raw)
	if err != nil {
		return store.NativeAdmission{}, err
	}
	return marker.NativeAdmission(), nil
}

// fetchGoModuleChecksumProof fetches only an explicitly configured authority.
// currentCheckpoint is a separately read retained timeline, not a response hint
// or automatic reset to initial trust. No database transaction is held here.
// This stages immutable proof bytes; it does not publish or advance trust.
func (s *Server) fetchGoModuleChecksumProof(parent context.Context, i store.Identity, repo store.Repository, c gomodule.Coordinate, zipHash, modHash string, currentCheckpoint []byte) (goChecksumFetch, error) {
	if _, err := gomodule.Canonical(c.Module, c.Version); err != nil || repo.Format != "go" || repo.Mode != "proxy" || repo.Settings.Upstream == nil || s.Blobs == nil || s.NativeMetadataBytes < 1 {
		return goChecksumFetch{}, store.ErrGoModuleUnvalidated
	}
	authority := repo.Settings.GoChecksumAuthority
	if authority == nil {
		return goChecksumFetch{}, errGoModuleChecksumRequired
	}
	if err := authority.Validate(); err != nil {
		return goChecksumFetch{}, err
	}
	if _, err := crypt.ParseGoSumDBCheckpoint(authority.VerifierKey, currentCheckpoint); err != nil {
		return goChecksumFetch{}, err
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	credential, err := s.credential(i.Tenant, authority.Endpoint)
	if err != nil {
		return goChecksumFetch{}, err
	}
	endpoint, err := upstream.New(authority.Endpoint, credential, s.PrivateUpstreamNetworks...)
	if err != nil {
		return goChecksumFetch{}, err
	}
	defer endpoint.Close()
	// Reserve each maximum body before contacting the authority. Failed reads
	// retain that reservation; successful shorter bodies refund unused bytes.
	// Detection consumes at most the reserved limit+1 bytes. Paths/attempts and
	// configured trust also consume this shared budget; headers use the common
	// transport's separate32KiB cap. The authenticated client caps attempts and
	// two concurrent readers, including full/partial-tile fallback.
	remaining := min(s.NativeMetadataBytes, int64(1<<20)) - int64(len(authority.VerifierKey)+len(currentCheckpoint)+len(c.Module)+len(c.Version)+512)
	var budget sync.Mutex
	read := func(ctx context.Context, path string, limit int64) ([]byte, error) {
		budget.Lock()
		cost := int64(len(path)) + limit + 1
		if cost > remaining {
			budget.Unlock()
			return nil, store.ErrMetadataLimit
		}
		remaining -= cost
		budget.Unlock()
		response, err := endpoint.Get(ctx, strings.TrimPrefix(path, "/"), http.Header{"Accept": {"text/plain, application/octet-stream"}})
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || response.ContentLength > limit || len(response.Header.Values("Content-Range")) != 0 || len(response.Trailer) != 0 {
			return nil, crypt.ErrGoChecksumAuthority
		}
		for _, name := range []string{"Content-Encoding", "Age", "Expires", "ETag", "Last-Modified"} {
			if len(response.Header.Values(name)) > 1 {
				return nil, crypt.ErrGoChecksumAuthority
			}
		}
		if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
			return nil, crypt.ErrGoChecksumAuthority
		}
		if _, _, err := cachePolicy(goModuleCacheHeaders(response.Header), repo, store.Retrieval{}, http.StatusOK); err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit || response.ContentLength >= 0 && response.ContentLength != int64(len(data)) {
			return nil, crypt.ErrGoChecksumAuthority
		}
		budget.Lock()
		remaining += limit + 1 - int64(len(data))
		budget.Unlock()
		return data, nil
	}
	trust := crypt.GoSumDBSnapshot{VerifierKey: authority.VerifierKey, Checkpoint: currentCheckpoint}
	verified, snapshot, err := crypt.CollectGoSumDB(ctx, c.Module, c.Version, zipHash, modHash, trust, read)
	if err != nil {
		return goChecksumFetch{}, err
	}
	proof := store.GoModuleChecksumProof{Profile: store.GoModuleChecksumProfile, Module: c.Module, Version: c.Version, ZIPHash: zipHash, ModHash: modHash, Snapshot: snapshot}
	replayed, err := store.VerifyGoModuleChecksumProof(ctx, proof, c, zipHash, modHash, authority.VerifierKey, currentCheckpoint)
	if err != nil {
		return goChecksumFetch{}, err
	}
	if !bytes.Equal(replayed.Checkpoint, verified.Checkpoint) {
		return goChecksumFetch{}, crypt.ErrGoChecksumAuthority
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return goChecksumFetch{}, err
	}
	limit := min(s.NativeMetadataBytes, int64(store.MaxGoModuleChecksumProof))
	if int64(len(raw)) > limit {
		return goChecksumFetch{}, store.ErrMetadataLimit
	}
	object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(raw), crypt.Digest(raw), int64(len(raw)))
	if err != nil {
		return goChecksumFetch{}, err
	}
	if err := ctx.Err(); err != nil {
		return goChecksumFetch{}, err
	}
	return goChecksumFetch{Proof: proof, Verified: verified, Object: object}, nil
}
