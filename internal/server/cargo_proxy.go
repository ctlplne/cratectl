// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/cargo"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func (s *Server) cargoProxyDownload(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, name, version string) {
	ctx := r.Context()
	key, err := cargo.NameKey(name)
	if err != nil {
		respondErr(w, store.ErrNotFound)
		return
	}
	p, err := store.CargoProxyPath(key, version)
	if err != nil {
		respondErr(w, store.ErrNotFound)
		return
	}
	force := forceRefresh(r)
	catalog, err := s.resolveProxy(ctx, i, repo, store.CargoCatalogPath(key), force)
	if err != nil {
		respondErr(w, err)
		return
	}
	binding, _, err := s.DB.CargoProxyBinding(ctx, i, repo.Name, key, version, repo.SourceRevision)
	if err != nil {
		respondErr(w, err)
		return
	}
	if binding.Version != version {
		respondErr(w, store.ErrNotFound)
		return
	}
	if binding.CatalogDigest != catalog.artifact.Digest {
		respondErr(w, store.ErrSourceChanged)
		return
	}
	resolved, err := s.resolveProxy(ctx, i, repo, p, force)
	if err != nil {
		respondErr(w, err)
		return
	}
	resolved.cargo = &cargoRead{repository: repo.Name, name: key, version: version, proxy: &binding}
	resolved.admissions = append(resolved.admissions, catalog.admissions...)
	s.serveResolvedArtifact(w, r, i, resolved)
}

func (s *Server) fillCargoProxy(ctx context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	if repo.Settings.Upstream == nil {
		return store.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	result := s.fetchCargo(ctx, i, repo, lease)
	complete := ctx
	if ctx.Err() != nil {
		result = store.RetrievalResult{Failure: "retrieval_cancelled"}
		var done context.CancelFunc
		complete, done = context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
	}
	return s.DB.CompleteRetrieval(complete, i, lease, result)
}

func (s *Server) fetchCargo(ctx context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) store.RetrievalResult {
	var binding store.CargoArchiveBinding
	var index cargo.SparseEntry
	config := *repo.Settings.Upstream
	name, catalog := strings.CutPrefix(lease.Path, "cargo-catalog/")
	var upstreamPath string
	var err error
	if catalog {
		upstreamPath, err = cargo.IndexPath(name)
		if err != nil {
			return store.RetrievalResult{Failure: "upstream_metadata_invalid"}
		}
	} else {
		crate, version, ok := store.CargoProxyCoordinate(lease.Path)
		if !ok {
			return store.RetrievalResult{Failure: "upstream_metadata_invalid"}
		}
		var data json.RawMessage
		binding, data, err = s.DB.CargoProxyBinding(ctx, i, repo.Name, crate, version, lease.SourceRevision)
		if err != nil || len(data) > 2*cargo.MaxIndexBytes || json.Unmarshal(data, &index) != nil ||
			index.Name != binding.Name || index.Version != binding.Version || index.Checksum != binding.Checksum {
			return store.RetrievalResult{Failure: "upstream_cargo_binding_changed"}
		}
		config, err = downloadSource(repo, binding.SourceURL)
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
	validators := http.Header{}
	validators.Set("If-None-Match", lease.ETag)
	validators.Set("If-Modified-Since", lease.Modified)
	var response *http.Response
	if catalog {
		response, err = endpoint.Get(ctx, upstreamPath, validators)
	} else {
		response, err = endpoint.GetURL(ctx, binding.SourceURL, validators)
	}
	if err != nil {
		return store.RetrievalResult{Failure: cargoTransportFailure(err)}
	}
	defer response.Body.Close()
	result := store.RetrievalResult{Status: response.StatusCode}
	switch response.StatusCode {
	case http.StatusOK, http.StatusNotModified:
		result.FreshSeconds, result.StaleSeconds, err = cachePolicy(response.Header, repo, lease, response.StatusCode)
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
		if !catalog {
			result.CargoBinding = &binding
		}
		if response.StatusCode == http.StatusNotModified {
			return result
		}
		if catalog {
			result.Failure = s.stageCargoCatalog(ctx, i, repo, endpoint, response, name, &result)
		} else {
			result.Failure = s.stageCargoArchive(ctx, i, repo, response, index, &result)
		}
	case http.StatusNotFound:
		repo.Settings.Cache.FreshSeconds = repo.Settings.Cache.NegativeSeconds
		result.FreshSeconds, _, _ = cachePolicy(response.Header, repo, lease, http.StatusNotFound)
	default:
		result.Failure = "upstream_rejected_request"
		if response.StatusCode >= 500 {
			result.Failure = "transient_upstream_failure"
		}
	}
	return result
}

func cargoIdentityEncoding(response *http.Response) bool {
	encoding := response.Header.Get("Content-Encoding")
	return encoding == "" || encoding == "identity"
}

func cargoTransportFailure(err error) string {
	if errors.Is(err, upstream.ErrDestination) || errors.Is(err, upstream.ErrRedirect) || errors.Is(err, upstream.ErrPath) {
		return "upstream_authority_failure"
	}
	return "transient_upstream_failure"
}

func (s *Server) stageCargoCatalog(ctx context.Context, i store.Identity, repo store.Repository, endpoint *upstream.Endpoint, response *http.Response, name string, result *store.RetrievalResult) string {
	data, err := io.ReadAll(io.LimitReader(response.Body, s.NativeMetadataBytes+1))
	if err != nil || int64(len(data)) > s.NativeMetadataBytes {
		return "upstream_metadata_budget"
	}
	entries, err := cargo.ParseSparseIndex(data, name, s.NativeVersionLimit)
	if err != nil {
		return "upstream_metadata_invalid"
	}
	config, err := endpoint.Get(ctx, "config.json", nil)
	if err != nil {
		return cargoTransportFailure(err)
	}
	defer config.Body.Close()
	if config.StatusCode != http.StatusOK || !cargoIdentityEncoding(config) {
		return "upstream_cargo_configuration"
	}
	const maxConfig = 16 << 10
	data, err = io.ReadAll(io.LimitReader(config.Body, maxConfig+1))
	if err != nil {
		return "upstream_cargo_configuration"
	}
	template, err := cargo.ParseDownloadTemplate(data)
	if err != nil {
		return "upstream_cargo_configuration"
	}
	authorities := []*upstream.Endpoint{endpoint}
	for _, source := range repo.Settings.DownloadSources {
		delivery, err := upstream.New(source, "")
		if err != nil {
			return "upstream_authority_failure"
		}
		defer delivery.Close()
		authorities = append(authorities, delivery)
	}
	publication := &store.NativeCatalogPublication{Name: name, Entries: make(map[string]string, len(entries)), Sources: make([]store.NativeSource, 0, len(entries))}
	for _, entry := range entries {
		download, err := cargo.DownloadURL(template, entry)
		if err != nil {
			return "upstream_cargo_configuration"
		}
		allowed := false
		for _, authority := range authorities {
			if authority.AllowsURL(download) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "upstream_authority_failure"
		}
		metadata, err := store.CargoCanonicalSource(entry)
		if err != nil {
			return "upstream_metadata_invalid"
		}
		version, _ := cargo.VersionKey(entry.Version)
		key := store.CargoSourceKey(name, entry.Version)
		publication.Entries[version] = key
		publication.Sources = append(publication.Sources, store.NativeSource{Key: key, Format: "cargo", Name: name,
			Coordinate: version, Version: entry.Version, URL: download, Integrity: "sha256:" + entry.Checksum, Metadata: metadata})
	}
	data, err = json.Marshal(store.CargoCatalog{Name: name, Entries: entries})
	if err != nil || int64(len(data)) > s.NativeMetadataBytes {
		return "upstream_metadata_budget"
	}
	object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), "", int64(len(data)))
	if err != nil {
		return "upstream_transfer_failure"
	}
	result.Object, result.Metadata, result.MediaType, result.NativeCatalog = &object, data, store.CargoCatalogMedia, publication
	return ""
}

func (s *Server) stageCargoArchive(ctx context.Context, i store.Identity, repo store.Repository, response *http.Response, entry cargo.SparseEntry, result *store.RetrievalResult) string {
	if response.ContentLength > cargo.MaxUploadBytes {
		return "upstream_archive_budget"
	}
	object, err := s.Blobs.Put(ctx, i.Tenant, io.LimitReader(response.Body, cargo.MaxUploadBytes+1), entry.Checksum, response.ContentLength)
	if errors.Is(err, blob.ErrDigest) {
		return "upstream_integrity_failure"
	}
	if err != nil || object.Size > cargo.MaxUploadBytes {
		return "upstream_transfer_failure"
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		return "upstream_integrity_failure"
	}
	defer file.Close()
	sparseIndex := "sparse+" + strings.TrimRight(repo.Settings.Upstream.URL, "/") + "/"
	archive, err := cargo.ReadArchive(ctx, file, cargo.Coordinate{Name: entry.Name, Version: entry.Version}, sparseIndex)
	if err != nil || !entry.MatchesArchive(archive) {
		return "upstream_cargo_archive_metadata_mismatch"
	}
	metadata, err := json.Marshal(result.CargoBinding)
	if err != nil {
		return "upstream_metadata_invalid"
	}
	result.Object, result.MediaType, result.Metadata = &object, cargo.MediaType, metadata
	return ""
}
