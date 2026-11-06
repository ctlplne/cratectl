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
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

var errGoModuleOriginMissing = errors.New("configured Go origin has no such version")
var errGoModuleOriginTransient = errors.New("temporary configured Go origin failure")
var errGoModuleChecksumRequired = errors.New("Go origin checksum authority is not configured")
var errGoModuleChecksumPublicationRequired = errors.New("Go checksum proofs require durable publication admission")

type goModuleOriginStatus struct{ status, fresh int }

func (e *goModuleOriginStatus) Error() string {
	return "configured Go origin response was not a complete representation"
}
func (e *goModuleOriginStatus) Unwrap() error {
	if e.status == 404 || e.status == 410 {
		return errGoModuleOriginMissing
	}
	if e.status >= 500 {
		return errGoModuleOriginTransient
	}
	return errUpstream
}

func goModuleCacheHeaders(header http.Header) http.Header {
	h := header.Clone()
	for _, name := range []string{"Cache-Control", "Vary"} {
		h.Set(name, strings.Join(h.Values(name), ","))
	}
	for _, field := range strings.Split(h.Get("Vary"), ",") {
		if strings.TrimSpace(field) == "*" {
			h.Set("Vary", "*")
			break
		}
	}
	return h
}

// fetchGoModuleCatalog stages the original upstream version advertisement. It
// does not approve listed packages, merge source precedence or enable discovery.
func (s *Server) fetchGoModuleCatalog(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) (store.RetrievalResult, error) {
	escaped, ok := strings.CutPrefix(lease.Path, "go-catalog/")
	request, e := gomodule.ParseRequest(escaped + "/@v/list")
	if !ok || e != nil || request.Operation != "list" || store.GoModuleCatalogPath(request.Module) != lease.Path || repo.Format != "go" || repo.Mode != "proxy" || repo.Name != lease.Repository || repo.SourceRevision != lease.SourceRevision || repo.Settings.Upstream == nil || s.Blobs == nil || s.NativeMetadataBytes < 1 {
		return store.RetrievalResult{}, store.ErrGoModuleUnvalidated
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	config := *repo.Settings.Upstream
	credential, e := s.credential(i.Tenant, config)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	endpoint, e := upstream.New(config, credential, s.PrivateUpstreamNetworks...)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	defer endpoint.Close()
	limit := min(s.NativeMetadataBytes, store.MaxGoModuleCatalog)
	object, data, fresh, stale, e := s.fetchGoRepresentation(ctx, i, repo, endpoint, escaped+"/@v/list", limit, true)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	catalog, e := store.NewGoModuleCatalog(request.Module, data, s.NativeVersionLimit, limit)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	metadata, e := json.Marshal(catalog)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	if object.Size+int64(len(metadata)) > limit {
		return store.RetrievalResult{}, store.ErrMetadataLimit
	}
	if e = ctx.Err(); e != nil {
		return store.RetrievalResult{}, e
	}
	return store.RetrievalResult{Status: http.StatusOK, Object: &object, Metadata: metadata, MediaType: store.GoModuleCatalogMedia, FreshSeconds: fresh, StaleSeconds: stale, GoCatalog: &catalog}, nil
}

// fetchGoModuleBundle retrieves and durably stages one complete immutable bundle.
// It never publishes references, grants approval, contacts a checksum service or
// resolves through VCS/direct fallback. CompleteRetrieval must subsequently fence
// the current tenant, source and lease in its common publication transaction.
// Public Go proxy mode remains disabled pending catalog and serving admission.
//
// All representations are fetched in full on refresh. A ZIP-only 304 cannot
// validate the independently supplied info/mod bytes; conditional refresh needs
// a separate, complete bundle validation contract before it can be enabled.
func (s *Server) fetchGoModuleBundle(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) (store.RetrievalResult, error) {
	request, e := gomodule.ParseRequest(lease.Path)
	if e != nil || request.Operation != "zip" || repo.Format != "go" || repo.Mode != "proxy" || repo.Name != lease.Repository || repo.SourceRevision != lease.SourceRevision || repo.Settings.Upstream == nil || s.Blobs == nil {
		return store.RetrievalResult{}, store.ErrGoModuleUnvalidated
	}
	if repo.Settings.GoChecksumAuthority != nil {
		return store.RetrievalResult{}, errGoModuleChecksumPublicationRequired
	}
	if repo.Settings.Cache.RequireChecksum {
		// Internal hashes bind the retrieved bytes; they are not an independent
		// checksum authority. Never silently satisfy require_checksum with them.
		return store.RetrievalResult{}, errGoModuleChecksumRequired
	}
	if s.GoModuleUploadBytes <= 0 || s.GoModuleUploadBytes >= 1<<62 || s.NativeMetadataBytes <= 0 {
		return store.RetrievalResult{}, store.ErrMetadataLimit
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	config := *repo.Settings.Upstream
	credential, e := s.credential(i.Tenant, config)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	endpoint, e := upstream.New(config, credential, s.PrivateUpstreamNetworks...)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	defer endpoint.Close()

	fresh, stale := repo.Settings.Cache.FreshSeconds, repo.Settings.Cache.StaleSeconds
	var mod, info []byte
	var zipObject blob.Object
	objects := make([]store.Artifact, 0, 3)
	metadata := store.GoModuleMetadata{Profile: store.GoModuleProfile, Module: request.Module, Version: request.Version, Digests: map[string]string{}}
	for _, representation := range []struct {
		kind, media string
		limit       int64
	}{{"info", "application/json", min(gomodule.MaxVersionInfo, s.NativeMetadataBytes)}, {"mod", "text/plain; charset=utf-8", min(gomodule.MaxGoMod, s.NativeMetadataBytes)}, {"zip", "application/zip", s.GoModuleUploadBytes}} {
		p := request.Coordinate.Prefix() + "." + representation.kind
		object, data, responseFresh, responseStale, err := s.fetchGoRepresentation(ctx, i, repo, endpoint, p, representation.limit, representation.kind != "zip")
		if err != nil {
			// Only absence of the initial version-info response denotes an absent
			// version. A missing sibling is incomplete intake, never a negative
			// cache entry authorizing a group's lower-priority source.
			if errors.Is(err, errGoModuleOriginMissing) && representation.kind != "info" {
				err = store.ErrGoModuleUnvalidated
			}
			return store.RetrievalResult{}, err
		}
		fresh, stale = min(fresh, responseFresh), min(stale, responseStale)
		switch representation.kind {
		case "info":
			if _, e = gomodule.ParseVersionInfo(data, request.Coordinate); e != nil {
				return store.RetrievalResult{}, e
			}
			info = data
		case "mod":
			mod = data
		case "zip":
			zipObject = object
		}
		metadata.Digests[representation.kind] = object.Digest
		objects = append(objects, store.Artifact{Path: p, Digest: object.Digest, Size: object.Size, MediaType: representation.media})
	}
	file, e := s.Blobs.OpenVerified(ctx, i.Tenant, zipObject.Digest, zipObject.Size)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	_, e = gomodule.InspectRepresentations(ctx, file, zipObject.Size, request.Coordinate, mod, info, ziparchive.Limits{CompressedBytes: s.GoModuleUploadBytes, ExpandedBytes: s.GoModuleExpandedBytes, DirectoryBytes: s.GoModuleDirectoryBytes, Files: s.GoModuleFileLimit})
	file.Close()
	if e != nil {
		return store.RetrievalResult{}, e
	}
	raw, e := json.Marshal(metadata)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	for n := range objects {
		objects[n].Metadata = raw
	}
	if e = ctx.Err(); e != nil {
		return store.RetrievalResult{}, e
	}
	return store.RetrievalResult{Status: http.StatusOK, Object: &zipObject, MediaType: "application/zip", Metadata: raw, FreshSeconds: fresh, StaleSeconds: stale, GoModule: &store.GoModulePublication{Objects: objects}}, nil
}

func (s *Server) fetchGoRepresentation(ctx context.Context, i store.Identity, repo store.Repository, endpoint *upstream.Endpoint, p string, limit int64, metadata bool) (blob.Object, []byte, int, int, error) {
	response, e := endpoint.Get(ctx, p, nil)
	if e != nil {
		return blob.Object{}, nil, 0, 0, e
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		negative := repo
		negative.Settings.Cache.FreshSeconds = repo.Settings.Cache.NegativeSeconds
		fresh, _, err := cachePolicy(goModuleCacheHeaders(response.Header), negative, store.Retrieval{}, 404)
		if err != nil || len(response.Header.Values("Age")) > 1 || len(response.Header.Values("Expires")) > 1 {
			fresh = 0
		}
		return blob.Object{}, nil, 0, 0, &goModuleOriginStatus{status: response.StatusCode, fresh: fresh}
	}
	if response.StatusCode != http.StatusOK {
		return blob.Object{}, nil, 0, 0, &goModuleOriginStatus{status: response.StatusCode}
	}
	// Multiple singleton headers are ambiguous. Join list-valued directives so
	// a second no-store/no-cache/Vary:* header cannot disappear behind Get.
	for _, name := range []string{"Content-Encoding", "Age", "Expires", "ETag", "Last-Modified"} {
		if len(response.Header.Values(name)) > 1 {
			return blob.Object{}, nil, 0, 0, errUpstream
		}
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" || len(response.Header.Values("Content-Range")) != 0 || len(response.Header.Get("ETag")) > 1024 || len(response.Header.Get("Last-Modified")) > 128 {
		return blob.Object{}, nil, 0, 0, errUpstream
	}
	headers := goModuleCacheHeaders(response.Header)
	fresh, stale, e := cachePolicy(headers, repo, store.Retrieval{}, http.StatusOK)
	if e != nil {
		return blob.Object{}, nil, 0, 0, e
	}
	if response.ContentLength > limit {
		return blob.Object{}, nil, 0, 0, store.ErrMetadataLimit
	}
	var data []byte
	var object blob.Object
	if metadata {
		data, e = io.ReadAll(io.LimitReader(response.Body, limit+1))
		if e != nil {
			return blob.Object{}, nil, 0, 0, e
		}
		if int64(len(data)) > limit {
			return blob.Object{}, nil, 0, 0, store.ErrMetadataLimit
		}
		if response.ContentLength >= 0 && int64(len(data)) != response.ContentLength {
			return blob.Object{}, nil, 0, 0, blob.ErrLength
		}
		object, e = s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), "", int64(len(data)))
	} else {
		object, e = s.Blobs.Put(ctx, i.Tenant, io.LimitReader(response.Body, limit+1), "", response.ContentLength)
		if e == nil && object.Size > limit {
			e = store.ErrMetadataLimit
		}
	}
	if e != nil {
		return blob.Object{}, nil, 0, 0, e
	}
	return object, data, fresh, stale, nil
}
