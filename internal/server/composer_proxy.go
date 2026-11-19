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

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/composer"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

type composerProxyContextKey struct{}

type composerProxyRead struct {
	catalogDigest string
	admissions    []store.NativeAdmission
}

func (s *Server) serveComposerProxy(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, coordinate composer.Coordinate) {
	digest, pinned := strings.CutPrefix(r.URL.RawQuery, "sha256=")
	path := store.ComposerProxyArchivePath(coordinate, digest)
	if _, _, ok := store.ParseComposerProxyArchive(path); !pinned || !ok {
		fail(w, 400, "composer_proxy_digest_required", "Use the SHA-256-pinned archive URL advertised in Composer metadata.")
		return
	}
	ctx := r.Context()
	catalog, err := s.resolveProxy(ctx, i, repo, store.ComposerCatalogPath(coordinate.Name, coordinate.Development()), forceRefresh(r))
	if err != nil {
		respondErr(w, err)
		return
	}
	plan := &composerProxyRead{catalogDigest: catalog.artifact.Digest, admissions: catalog.admissions}
	if _, err = s.DB.ComposerProxyBinding(ctx, i, repo, coordinate, digest, plan.catalogDigest,
		s.NativeVersionLimit, s.NativeMetadataBytes, plan.admissions); err != nil {
		respondErr(w, err)
		return
	}
	authorized := context.WithValue(ctx, composerProxyContextKey{}, plan)
	resolved, err := s.resolveProxy(authorized, i, repo, path, forceRefresh(r))
	if err != nil {
		respondErr(w, err)
		return
	}
	resolved.composerProxy = plan
	resolved.admissions = append(resolved.admissions, plan.admissions...)
	s.serveResolvedArtifact(w, r, i, resolved)
}

func (s *Server) composerProxyVersions(r *http.Request, i store.Identity, repo store.Repository, base, name string, development bool) ([]composerVersion, error) {
	ctx := r.Context()
	catalog, err := s.resolveProxy(ctx, i, repo, store.ComposerCatalogPath(name, development), forceRefresh(r))
	if err != nil {
		return nil, err
	}
	versions, err := s.DB.ComposerProxyVersions(ctx, i, repo, catalog.artifact, s.NativeVersionLimit, s.NativeMetadataBytes, catalog.admissions)
	if err != nil {
		return nil, err
	}
	rows := make([]composerVersion, 0, len(versions))
	for _, version := range versions {
		coordinate := version.Coordinate()
		rows = append(rows, composerVersion{Package: version.Package, Normalized: coordinate.NormalizedVersion(), Dist: composerDist{
			Type: "zip", URL: s.PublicURL + base + coordinate.Path() + "?sha256=" + version.SHA256,
			Reference: version.SHA256, SHA1: version.SHA1,
		}})
	}
	return rows, nil
}

func (s *Server) fillComposerProxy(ctx context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	result := s.fetchComposerProxy(ctx, i, repo, lease)
	if ctx.Err() == nil {
		return s.DB.CompleteRetrieval(ctx, i, lease, result)
	}
	complete, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	return s.DB.CompleteRetrieval(complete, i, lease, store.RetrievalResult{Failure: "retrieval_cancelled"})
}

func (s *Server) fetchComposerProxy(ctx context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) store.RetrievalResult {
	if repo.Settings.Upstream == nil {
		return store.RetrievalResult{Failure: "upstream_authority_failure"}
	}
	config := *repo.Settings.Upstream
	name, development, catalog := store.ParseComposerCatalogPath(lease.Path)
	var entry composer.RemoteDistribution
	if !catalog {
		coordinate, digest, ok := store.ParseComposerProxyArchive(lease.Path)
		plan, planned := ctx.Value(composerProxyContextKey{}).(*composerProxyRead)
		if !ok || !planned || plan == nil {
			return store.RetrievalResult{Failure: "upstream_composer_binding_changed"}
		}
		var err error
		entry, err = s.DB.ComposerProxyBinding(ctx, i, repo, coordinate, digest, plan.catalogDigest, s.NativeVersionLimit, s.NativeMetadataBytes, plan.admissions)
		if err != nil {
			return store.RetrievalResult{Failure: "upstream_composer_binding_changed"}
		}
		config, err = downloadSource(repo, entry.URL)
		if err != nil {
			return store.RetrievalResult{Failure: "upstream_authority_failure"}
		}
	}
	credential, err := s.credential(i.Tenant, config)
	if err != nil {
		return store.RetrievalResult{Failure: "upstream_credential_authority"}
	}
	endpoint, err := upstream.New(config, credential, s.PrivateUpstreamNetworks...)
	if err != nil {
		return store.RetrievalResult{Failure: "upstream_authority_failure"}
	}
	defer endpoint.Close()
	headers := http.Header{"If-None-Match": {lease.ETag}, "If-Modified-Since": {lease.Modified}}
	var response *http.Response
	if catalog {
		path := "p2/" + name
		if development {
			path += "~dev"
		}
		response, err = endpoint.Get(ctx, path+".json", headers)
	} else {
		response, err = endpoint.GetURL(ctx, entry.URL, headers)
	}
	if err != nil {
		return store.RetrievalResult{Failure: cargoTransportFailure(err)}
	}
	defer response.Body.Close()
	result := store.RetrievalResult{Status: response.StatusCode}
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
			result.Failure = s.stageComposerCatalog(ctx, i, repo, name, development, response.Body, &result)
		} else {
			result.Failure = s.stageComposerProxyArchive(ctx, i, entry, response, &result)
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

func (s *Server) stageComposerCatalog(ctx context.Context, i store.Identity, repo store.Repository, name string, development bool,
	body io.Reader, result *store.RetrievalResult) string {
	limit := min(int64(composer.CatalogBytes), s.NativeMetadataBytes)
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return "upstream_metadata_budget"
	}
	versions, err := composer.ParseCatalog(ctx, raw, name, development, min(10000, s.NativeVersionLimit), limit)
	if err != nil {
		return "upstream_metadata_invalid"
	}
	catalog := store.ComposerProxyCatalog{Name: name, Development: development, Distributions: []composer.RemoteDistribution{}}
	for _, entry := range versions {
		if ctx.Err() != nil {
			return "retrieval_cancelled"
		}
		if entry.SHA256 == "" {
			continue
		}
		if _, err := downloadSource(repo, entry.URL); err != nil {
			return "upstream_authority_failure"
		}
		catalog.Distributions = append(catalog.Distributions, entry)
	}
	data, err := json.Marshal(catalog)
	if err != nil || int64(len(data)) > limit {
		return "upstream_metadata_budget"
	}
	object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), "", int64(len(data)))
	if err != nil {
		return "upstream_transfer_failure"
	}
	result.Object, result.MediaType, result.Metadata = &object, store.ComposerCatalogMedia, data
	return ""
}

func (s *Server) stageComposerProxyArchive(ctx context.Context, i store.Identity, entry composer.RemoteDistribution,
	response *http.Response, result *store.RetrievalResult) string {
	if response.ContentLength > composer.UploadBytes {
		return "upstream_archive_budget"
	}
	hash := crypt.CompatibilityHash("sha1")
	reader := io.TeeReader(io.LimitReader(response.Body, composer.UploadBytes+1), hash)
	object, err := s.Blobs.Put(ctx, i.Tenant, reader, entry.SHA256, response.ContentLength)
	if errors.Is(err, blob.ErrDigest) || errors.Is(err, blob.ErrIntegrity) {
		return "upstream_integrity_failure"
	}
	if err != nil || object.Size > composer.UploadBytes {
		return "upstream_transfer_failure"
	}
	sha1 := hex.EncodeToString(hash.Sum(nil))
	if entry.SHA1 != "" && entry.SHA1 != sha1 {
		return "upstream_integrity_failure"
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		return "upstream_integrity_failure"
	}
	defer file.Close()
	meta, err := composer.Inspect(ctx, file, object.Size, entry.Coordinate())
	if err != nil {
		return "upstream_archive_invalid"
	}
	if !entry.Package.SameInstallation(meta) {
		return "upstream_composer_binding_changed"
	}
	data, err := json.Marshal(store.ComposerPackage{Package: meta, SHA1: sha1, Validated: true})
	if err != nil {
		return "upstream_metadata_invalid"
	}
	result.Object, result.MediaType, result.Metadata = &object, store.ComposerMedia, data
	return ""
}
