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

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func (s *Server) fillPythonProxy(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	if repo.Settings.Upstream == nil {
		return store.ErrConflict
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	result := store.RetrievalResult{FreshSeconds: repo.Settings.Cache.NegativeSeconds}
	catalogRequest := strings.HasPrefix(lease.Path, "pypi-catalog/")
	config := *repo.Settings.Upstream
	var source store.NativeSource
	var expected store.PythonFile
	var e error
	if !catalogRequest {
		parts := strings.Split(lease.Path, "/")
		if len(parts) != 4 || parts[0] != "pypi-packages" {
			return store.ErrConflict
		}
		source, e = s.DB.NativeSource(ctx, i, repo.Name, parts[2], "pypi")
		if e != nil {
			return e
		}
		if source.Name != parts[1] || source.Coordinate != parts[3] || json.Unmarshal(source.Metadata, &expected) != nil {
			return store.ErrConflict
		}
		config, e = downloadSource(repo, source.URL)
	}
	validators := http.Header{}
	if lease.ETag != "" {
		validators.Set("If-None-Match", lease.ETag)
	}
	if lease.Modified != "" {
		validators.Set("If-Modified-Since", lease.Modified)
	}
	if catalogRequest {
		validators.Set("Accept", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1")
		if repo.Settings.PythonIndexFormat == "html" {
			validators.Set("Accept", "text/html")
		} else if repo.Settings.PythonIndexFormat == "json" {
			validators.Set("Accept", "application/vnd.pypi.simple.v1+json")
		}
	}
	var response *http.Response
	if e == nil {
		var credential string
		credential, e = s.credential(i.Tenant, config)
		if e == nil {
			var endpoint *upstream.Endpoint
			endpoint, e = upstream.New(config, credential, s.PrivateUpstreamNetworks...)
			if e == nil {
				defer endpoint.Close()
				if catalogRequest {
					response, e = endpoint.GetIndex(ctx, strings.TrimPrefix(lease.Path, "pypi-catalog/"), validators)
				} else {
					response, e = endpoint.GetURL(ctx, source.URL, validators)
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
			result.FreshSeconds, result.StaleSeconds, e = cachePolicy(response.Header, repo, lease, result.Status)
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
				catalog, sources, err := s.parsePythonIndex(data, response.Header.Get("Content-Type"), response.Request.URL.String(), strings.TrimPrefix(lease.Path, "pypi-catalog/"), repo)
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
				result.Object, result.Metadata, result.MediaType = &object, encoded, store.PythonCatalogMedia
				result.NativeCatalog = &store.NativeCatalogPublication{Name: catalog.Name, Entries: catalog.Files, Sources: sources}
			} else {
				if response.ContentLength > s.PythonUploadBytes {
					result.Failure = "upstream_archive_budget"
					break
				}
				object, err := s.Blobs.Put(ctx, i.Tenant, io.LimitReader(response.Body, s.PythonUploadBytes+1), "", response.ContentLength)
				if err != nil || object.Size > s.PythonUploadBytes {
					result.Failure = "upstream_transfer_failure"
					break
				}
				if expected.Size != nil && object.Size != *expected.Size {
					result.Failure = "upstream_integrity_failure"
					break
				}
				file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
				if err != nil {
					result.Failure = "upstream_integrity_failure"
					break
				}
				pin, err := crypt.ParseSourceIntegrity(source.Integrity, "", false)
				if err == nil {
					err = pin.Verify(file)
				}
				if err != nil {
					file.Close()
					result.Failure = "upstream_integrity_failure"
					break
				}
				core, err := inspectPythonDistribution(ctx, file, object.Size, source.Coordinate, pythonArchiveBudget{s.PythonExpandedBytes, s.PythonFileLimit, s.PythonMetadataBytes})
				file.Close()
				if err != nil {
					result.Failure = "upstream_archive_invalid"
					break
				}
				if core.Name != source.Name || (expected.RequiresPython != "" && strings.Join(strings.Fields(core.RequiresPython), "") != strings.Join(strings.Fields(expected.RequiresPython), "")) {
					result.Failure = "upstream_python_metadata_mismatch"
					break
				}
				if expected.CoreIntegrity != "" {
					pin, err := crypt.ParseSourceIntegrity(expected.CoreIntegrity, "", false)
					if err == nil {
						err = pin.Verify(strings.NewReader(core.Raw))
					}
					if err != nil {
						result.Failure = "upstream_python_metadata_mismatch"
						break
					}
				}
				expected.Name, expected.Version, expected.RequiresPython = core.Name, core.Version, core.RequiresPython
				expected.CoreMetadata, expected.CoreSHA256 = core.Raw, crypt.Digest([]byte(core.Raw))
				expected.Validated = true
				expected.Size = &object.Size
				expected.SourceKey, expected.SourceURL = source.Key, source.URL
				result.Metadata, _ = json.Marshal(expected)
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
