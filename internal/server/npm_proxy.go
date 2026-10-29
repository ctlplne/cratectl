// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func downloadSource(repo store.Repository, raw string) (upstream.Config, error) {
	if repo.Settings.Upstream == nil {
		return upstream.Config{}, upstream.ErrDestination
	}
	sources := append([]upstream.Config{*repo.Settings.Upstream}, repo.Settings.DownloadSources...)
	var selected upstream.Config
	for _, source := range sources {
		endpoint, e := upstream.New(source, "")
		if e != nil {
			return selected, e
		}
		allowed := endpoint.AllowsURL(raw)
		endpoint.Close()
		if allowed && len(source.URL) > len(selected.URL) {
			selected = source
		}
	}
	if selected.URL == "" {
		return selected, upstream.ErrDestination
	}
	return selected, nil
}

func (s *Server) parseNPMCatalog(data []byte, name string, repo store.Repository) (store.NPMCatalog, []store.NPMSource, error) {
	catalog := store.NPMCatalog{Name: name, Versions: map[string]string{}, Tags: map[string]string{}}
	var raw struct {
		Name     string                     `json:"name"`
		Versions map[string]json.RawMessage `json:"versions"`
		Tags     map[string]string          `json:"dist-tags"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&raw) != nil || raw.Name != name || raw.Versions == nil {
		return catalog, nil, errUpstream
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return catalog, nil, errUpstream
	}
	if len(raw.Versions) > s.NativeVersionLimit || len(raw.Tags) > s.NativeTagLimit {
		return catalog, nil, store.ErrMetadataLimit
	}
	sources := make([]store.NPMSource, 0, len(raw.Versions))
	for version, value := range raw.Versions {
		var pkg map[string]any
		if !validNPMVersion(version) || json.Unmarshal(value, &pkg) != nil || pkg["name"] != name || pkg["version"] != version {
			return catalog, nil, errUpstream
		}
		dist, ok := pkg["dist"].(map[string]any)
		if !ok {
			return catalog, nil, errUpstream
		}
		tarball, ok := dist["tarball"].(string)
		if !ok {
			return catalog, nil, errUpstream
		}
		if _, e := downloadSource(repo, tarball); e != nil {
			return catalog, nil, e
		}
		integrity, _ := dist["integrity"].(string)
		shasum, _ := dist["shasum"].(string)
		pin, e := crypt.ParseSourceIntegrity(integrity, shasum, repo.Settings.Cache.AllowLegacyNPM && !repo.Settings.Cache.RequireChecksum)
		if e != nil {
			return catalog, nil, e
		}
		// The client receives a local tarball URL and the pinned integrity only.
		// Upstream signature/attestation fields are not promoted into a verdict.
		pkg["dist"] = map[string]any{"integrity": pin.Canonical}
		encoded, e := json.Marshal(pkg)
		if e != nil {
			return catalog, nil, e
		}
		source := store.NPMSource{Name: name, Version: version, Tarball: tarball, Integrity: pin.Canonical, Package: encoded}
		identity, _ := json.Marshal(source)
		source.Key = crypt.Digest(identity)
		catalog.Versions[version] = source.Key
		sources = append(sources, source)
	}
	for tag, version := range raw.Tags {
		if !validNPMTag(tag) || catalog.Versions[version] == "" {
			return catalog, nil, errUpstream
		}
		catalog.Tags[tag] = version
	}
	return catalog, sources, nil
}

func (s *Server) fillNPMProxy(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	if repo.Settings.Upstream == nil {
		return store.ErrConflict
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	result := store.RetrievalResult{FreshSeconds: repo.Settings.Cache.NegativeSeconds}
	var source store.NPMSource
	var response *http.Response
	var e error
	validators := http.Header{}
	if lease.ETag != "" {
		validators.Set("If-None-Match", lease.ETag)
	}
	if lease.Modified != "" {
		validators.Set("If-Modified-Since", lease.Modified)
	}
	catalogRequest := strings.HasPrefix(lease.Path, "npm-catalog/")
	var config upstream.Config
	if catalogRequest {
		config = *repo.Settings.Upstream
	} else {
		parts := strings.Split(lease.Path, "/-/cratectl/")
		if len(parts) != 2 || !npmName.MatchString(parts[0]) || !strings.HasSuffix(parts[1], ".tgz") {
			return store.ErrConflict
		}
		source, e = s.DB.NPMSource(ctx, i, repo.Name, strings.TrimSuffix(parts[1], ".tgz"), lease.SourceRevision)
		if e != nil {
			return e
		}
		if source.Name != parts[0] {
			return store.ErrNotFound
		}
		config, e = downloadSource(repo, source.Tarball)
	}
	if e == nil {
		var credential string
		credential, e = s.credential(i.Tenant, config)
		if e == nil {
			var endpoint *upstream.Endpoint
			endpoint, e = upstream.New(config, credential, s.PrivateUpstreamNetworks...)
			if e == nil {
				defer endpoint.Close()
				if catalogRequest {
					response, e = endpoint.GetPackage(ctx, strings.TrimPrefix(lease.Path, "npm-catalog/"), validators)
				} else {
					response, e = endpoint.GetURL(ctx, source.Tarball, validators)
				}
			}
		} else {
			result.Failure = "upstream_credential_authority"
		}
	}
	if e != nil {
		if result.Failure == "" {
			result.Failure = "transient_upstream_failure"
		}
		if errors.Is(e, upstream.ErrDestination) || errors.Is(e, upstream.ErrRedirect) || errors.Is(e, upstream.ErrPath) {
			result.Failure = "upstream_authority_failure"
		}
	} else {
		defer response.Body.Close()
		result.Status = response.StatusCode
		switch response.StatusCode {
		case 200, 304:
			result.FreshSeconds, result.StaleSeconds, e = cachePolicy(response.Header, repo, lease, response.StatusCode)
			if e != nil {
				result.Failure = "upstream_cache_policy_failure"
				break
			}
			if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
				result.Failure = "unexpected_upstream_encoding"
				break
			}
			result.ETag, result.Modified = response.Header.Get("ETag"), response.Header.Get("Last-Modified")
			if len(result.ETag) > 1024 || len(result.Modified) > 128 {
				result.Failure = "upstream_header_limit"
				break
			}
			if result.Status == 304 {
				break
			}
			if catalogRequest {
				data, err := io.ReadAll(io.LimitReader(response.Body, s.NativeMetadataBytes+1))
				if err != nil || int64(len(data)) > s.NativeMetadataBytes {
					result.Failure = "upstream_metadata_budget"
					break
				}
				catalog, sources, err := s.parseNPMCatalog(data, strings.TrimPrefix(lease.Path, "npm-catalog/"), repo)
				if err != nil {
					result.Failure = "upstream_metadata_invalid"
					break
				}
				encoded, _ := json.Marshal(catalog)
				object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(encoded), "", int64(len(encoded)))
				if err != nil {
					result.Failure = "upstream_transfer_failure"
					break
				}
				result.Object, result.Metadata, result.MediaType = &object, encoded, store.NPMCatalogMedia
				result.NPMCatalog, result.NPMSources = &catalog, sources
			} else {
				if response.ContentLength > s.NPMPublishBytes {
					result.Failure = "upstream_archive_budget"
					break
				}
				object, err := s.Blobs.Put(ctx, i.Tenant, io.LimitReader(response.Body, s.NPMPublishBytes+1), "", response.ContentLength)
				if err != nil || object.Size > s.NPMPublishBytes {
					result.Failure = "upstream_transfer_failure"
					break
				}
				file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
				if err != nil {
					result.Failure = "upstream_integrity_failure"
					break
				}
				pin, err := crypt.ParseSourceIntegrity(source.Integrity, "", repo.Settings.Cache.AllowLegacyNPM && !repo.Settings.Cache.RequireChecksum)
				if err == nil {
					err = pin.Verify(file)
				}
				if err != nil {
					file.Close()
					result.Failure = "upstream_integrity_failure"
					break
				}
				_, err = file.Seek(0, io.SeekStart)
				var data []byte
				if err == nil {
					data, err = io.ReadAll(io.LimitReader(file, s.NPMPublishBytes+1))
				}
				file.Close()
				if err != nil {
					result.Failure = "upstream_transfer_failure"
					break
				}
				pkg, err := npmArchivePackage(data, source.Name, source.Version, s.NPMExpandedBytes, s.NPMFileLimit, s.NPMPackageJSONBytes)
				if err != nil || !npmGraphMatches(pkg, source.Package) {
					result.Failure = "upstream_package_metadata_mismatch"
					break
				}
				pkg["dist"] = map[string]any{"integrity": source.Integrity, "shasum": crypt.SHA1(data)}
				algorithm, _, _ := strings.Cut(pin.Canonical, "-")
				result.Metadata, _ = json.Marshal(map[string]any{"name": source.Name, "version": source.Version, "package": pkg, "integrity": source.Integrity, "source_key": source.Key, "source_repository": repo.Name, "source_authority": config.URL, "source_url": source.Tarball, "upstream_checksum": algorithm + "_verified"})
				result.Object = &object
			}
		case 404:
			negative := repo
			negative.Settings.Cache.FreshSeconds = repo.Settings.Cache.NegativeSeconds
			fresh, _, err := cachePolicy(response.Header, negative, lease, 404)
			if err != nil {
				fresh = 0
			}
			result.FreshSeconds = fresh
		default:
			result.Failure = "upstream_rejected_request"
			if response.StatusCode >= 500 {
				result.Failure = "transient_upstream_failure"
			}
		}
	}
	if ctx.Err() != nil {
		result.Object = nil
		result.Failure = "retrieval_cancelled"
		complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer done()
		return s.DB.CompleteRetrieval(complete, i, lease, result)
	}
	return s.DB.CompleteRetrieval(ctx, i, lease, result)
}

func npmGraphMatches(pkg map[string]any, raw json.RawMessage) bool {
	var advertised map[string]any
	if json.Unmarshal(raw, &advertised) != nil {
		return false
	}
	for _, document := range []map[string]any{pkg, advertised} {
		for _, field := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
			if value := document[field]; value != nil {
				if _, ok := value.(map[string]any); !ok {
					return false
				}
			}
		}
	}
	for _, field := range []string{"dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "bundleDependencies", "bin", "engines", "os", "cpu"} {
		left, right := npmGraphField(pkg, field), npmGraphField(advertised, field)
		if m, ok := left.(map[string]any); ok && len(m) == 0 {
			left = nil
		}
		if m, ok := right.(map[string]any); ok && len(m) == 0 {
			right = nil
		}
		a, _ := json.Marshal(left)
		b, _ := json.Marshal(right)
		if !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}
func npmGraphField(pkg map[string]any, field string) any {
	value := pkg[field]
	switch field {
	case "bin":
		if target, ok := value.(string); ok {
			name, _ := pkg["name"].(string)
			return map[string]any{path.Base(name): path.Clean(strings.ReplaceAll(target, `\`, "/"))}
		}
		if targets, ok := value.(map[string]any); ok {
			normalized := map[string]any{}
			for name, target := range targets {
				if text, ok := target.(string); ok {
					normalized[name] = path.Clean(strings.ReplaceAll(text, `\`, "/"))
				} else {
					normalized[name] = target
				}
			}
			return normalized
		}
	case "dependencies":
		deps := map[string]any{}
		if values, ok := value.(map[string]any); ok {
			for k, v := range values {
				deps[k] = v
			}
		}
		if values, ok := pkg["optionalDependencies"].(map[string]any); ok {
			for k, v := range values {
				deps[k] = v
			}
		}
		return deps
	case "bundleDependencies":
		if value == nil {
			value = pkg["bundledDependencies"]
		}
		if enabled, ok := value.(bool); ok {
			if !enabled {
				return nil
			}
			keys := []string{}
			for name := range npmGraphField(pkg, "dependencies").(map[string]any) {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			if len(keys) == 0 {
				return nil
			}
			return keys
		}
		if items, ok := value.([]any); ok {
			keys := []string{}
			for _, item := range items {
				name, ok := item.(string)
				if !ok {
					return value
				}
				keys = append(keys, name)
			}
			sort.Strings(keys)
			if len(keys) == 0 {
				return nil
			}
			return keys
		}
	}
	return value
}
