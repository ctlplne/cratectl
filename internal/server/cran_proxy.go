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
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/cran"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

type cranProxyContextKey struct{}

func (s *Server) cranProxyIndex(r *http.Request, i store.Identity, repo store.Repository) (string, error) {
	catalog, err := s.resolveProxy(r.Context(), i, repo, store.CRANProxyCatalogPath, forceRefresh(r))
	if err != nil {
		return "", err
	}
	return s.DB.CRANProxyIndex(r.Context(), i, repo, catalog.artifact.Digest, s.NativeVersionLimit, s.NativeMetadataBytes, catalog.admissions)
}

func (s *Server) serveCRANProxyPackage(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, path string) {
	if _, _, valid := cran.ParsePinnedSourcePath(path); !valid {
		respondErr(w, store.ErrNotFound)
		return
	}
	ctx := r.Context()
	force := forceRefresh(r)
	catalog, err := s.resolveProxy(ctx, i, repo, store.CRANProxyCatalogPath, force)
	if err != nil {
		respondErr(w, err)
		return
	}
	plan := &store.CRANProxyAdmission{CatalogDigest: catalog.artifact.Digest, Generations: catalog.admissions}
	if _, err := s.DB.CRANProxyBinding(ctx, i, repo, path, plan.CatalogDigest, plan.Generations); err != nil {
		respondErr(w, err)
		return
	}
	ctx = context.WithValue(ctx, cranProxyContextKey{}, plan)
	resolved, err := s.resolveProxy(ctx, i, repo, path, force)
	if err != nil {
		respondErr(w, err)
		return
	}
	resolved.cranProxy = plan
	resolved.admissions = append(resolved.admissions, plan.Generations...)
	s.serveResolvedArtifact(w, r, i, resolved)
}

func (s *Server) fillCRANProxy(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	result := s.fetchCRANProxy(ctx, i, repo, lease)
	if ctx.Err() == nil {
		return s.DB.CompleteRetrieval(ctx, i, lease, result)
	}
	complete, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	return s.DB.CompleteRetrieval(complete, i, lease, store.RetrievalResult{Failure: "retrieval_cancelled"})
}

func (s *Server) fetchCRANProxy(ctx context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) store.RetrievalResult {
	if repo.Settings.Upstream == nil {
		return store.RetrievalResult{Failure: "upstream_authority_failure"}
	}
	catalog := lease.Path == store.CRANProxyCatalogPath
	path := cran.SourceDirectory + "PACKAGES"
	var entry cran.CatalogEntry
	var plan *store.CRANProxyAdmission
	if !catalog {
		plan, _ = ctx.Value(cranProxyContextKey{}).(*store.CRANProxyAdmission)
		if plan == nil {
			return store.RetrievalResult{Failure: "upstream_cran_binding_changed"}
		}
		var err error
		entry, err = s.DB.CRANProxyBinding(ctx, i, repo, lease.Path, plan.CatalogDigest, plan.Generations)
		if err != nil {
			return store.RetrievalResult{Failure: "upstream_cran_binding_changed"}
		}
		path = entry.Coordinate().Path()
	}
	config := *repo.Settings.Upstream
	credential, err := s.credential(i.Tenant, config)
	if err != nil {
		return store.RetrievalResult{Failure: "upstream_credential_authority"}
	}
	endpoint, err := upstream.New(config, credential, s.PrivateUpstreamNetworks...)
	if err != nil {
		return store.RetrievalResult{Failure: "upstream_authority_failure"}
	}
	defer endpoint.Close()
	response, err := endpoint.Get(ctx, path, http.Header{"If-None-Match": {lease.ETag}, "If-Modified-Since": {lease.Modified}})
	if err != nil {
		return store.RetrievalResult{Failure: cargoTransportFailure(err)}
	}
	defer response.Body.Close()
	result := store.RetrievalResult{Status: response.StatusCode, CRANProxy: plan}
	switch response.StatusCode {
	case http.StatusOK, http.StatusNotModified:
		result.FreshSeconds, _, err = cachePolicy(response.Header, repo, lease, response.StatusCode)
		if err != nil {
			result.Failure = "upstream_cache_policy_failure"
			return result
		}
		if !cargoIdentityEncoding(response) {
			result.Failure = "unexpected_upstream_encoding"
			return result
		}
		result.ETag, result.Modified = response.Header.Get("ETag"), response.Header.Get("Last-Modified")
		if len(result.ETag) > 1024 || len(result.Modified) > 128 {
			result.Failure = "upstream_header_limit"
			return result
		}
		if response.StatusCode == http.StatusNotModified {
			return result
		}
		if catalog {
			result.Failure = s.stageCRANProxyCatalog(ctx, i, response.Body, &result)
		} else {
			result.Failure = s.stageCRANProxyArchive(ctx, i, entry, response, &result)
		}
	case http.StatusNotFound:
		repo.Settings.Cache.FreshSeconds = repo.Settings.Cache.NegativeSeconds
		result.FreshSeconds, _, _ = cachePolicy(response.Header, repo, lease, response.StatusCode)
	default:
		result.Failure = "upstream_rejected_request"
		if response.StatusCode >= 500 {
			result.Failure = "transient_upstream_failure"
		}
	}
	return result
}

func (s *Server) stageCRANProxyCatalog(ctx context.Context, i store.Identity, input io.Reader, result *store.RetrievalResult) string {
	limit := min(int64(cran.MaxCatalogBytes), s.NativeMetadataBytes)
	raw, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return "upstream_metadata_budget"
	}
	entries, err := cran.ParseProxyCatalog(ctx, raw, s.NativeVersionLimit, limit)
	if err != nil {
		return "upstream_metadata_invalid"
	}
	catalog := make(map[string]cran.CatalogEntry, len(entries))
	for _, entry := range entries {
		catalog[entry.Coordinate().Path()] = entry
	}
	metadata, err := json.Marshal(catalog)
	if err != nil || int64(len(metadata)) > limit {
		return "upstream_metadata_budget"
	}
	object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(metadata), "", int64(len(metadata)))
	if err != nil {
		return "upstream_transfer_failure"
	}
	result.Object, result.MediaType, result.Metadata = &object, store.CRANProxyCatalogMedia, metadata
	return ""
}

func (s *Server) stageCRANProxyArchive(ctx context.Context, i store.Identity, entry cran.CatalogEntry, response *http.Response, result *store.RetrievalResult) string {
	if response.ContentLength > cran.MaxArchiveBytes {
		return "upstream_archive_budget"
	}
	checksum := crypt.CompatibilityHash("md5")
	reader := io.TeeReader(io.LimitReader(response.Body, cran.MaxArchiveBytes+1), checksum)
	object, err := s.Blobs.Put(ctx, i.Tenant, reader, entry.SHA256, response.ContentLength)
	if errors.Is(err, blob.ErrDigest) || errors.Is(err, blob.ErrIntegrity) {
		return "upstream_integrity_failure"
	}
	if err != nil || object.Size > cran.MaxArchiveBytes {
		return "upstream_transfer_failure"
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		return "upstream_integrity_failure"
	}
	defer file.Close()
	metadata, err := cran.Inspect(ctx, file, object.Size, entry.Coordinate())
	if err != nil {
		return "upstream_archive_invalid"
	}
	md5 := hex.EncodeToString(checksum.Sum(nil))
	if !entry.Matches(metadata, md5) {
		return "upstream_cran_binding_changed"
	}
	encoded, err := json.Marshal(store.CRANPackage{Description: metadata, MD5: md5, Validated: true})
	if err != nil {
		return "upstream_metadata_invalid"
	}
	result.Object, result.MediaType, result.Metadata = &object, store.CRANMedia, encoded
	return ""
}
