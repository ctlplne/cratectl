// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

// Recover locators from verified original manifest bytes, never from a durable
// URL binding. This also works for direct digest refresh after a process restart.
func (g *ociGraphFill) retainedDescriptor(kind string, expected *store.OCIDescriptor) ([]string, error) {
	if g.server.DB == nil {
		return nil, nil
	}
	parents, e := g.server.DB.OCIReferenceParents(g.ctx, g.identity, g.repo.Name, g.image, kind, expected.Digest, g.server.OCIDescriptorParents, g.server.NativeMetadataBytes-g.metadata)
	if e != nil {
		return nil, e
	}
	urls := []string{}
	seen := map[string]bool{}
	for _, a := range parents {
		if a.Size > ociManifestBytes {
			return nil, store.ErrMetadataLimit
		}
		input, e := g.server.Blobs.OpenVerified(g.ctx, g.identity.Tenant, a.Digest, a.Size)
		if e != nil {
			return nil, errUpstreamIntegrity
		}
		raw, e := io.ReadAll(io.LimitReader(input, ociManifestBytes+1))
		input.Close()
		if e != nil || len(raw) > ociManifestBytes {
			return nil, errUpstreamIntegrity
		}
		g.metadata += int64(len(raw))
		if g.metadata > g.server.NativeMetadataBytes {
			return nil, store.ErrMetadataLimit
		}
		m, e := parseOCIManifest(raw, a.MediaType)
		if e != nil {
			return nil, errUpstreamIntegrity
		}
		var metadata store.OCIManifestMetadata
		if json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated {
			return nil, errUpstreamIntegrity
		}
		take := func(d store.OCIDescriptor, locators []string) error {
			if expected.Digest != d.Digest {
				return nil
			}
			if expected.Size >= 0 && (expected.Size != d.Size || kind == "manifests" && expected.MediaType != d.MediaType) {
				return errUpstreamIntegrity
			}
			*expected = d
			for _, locator := range locators {
				if seen[locator] {
					continue
				}
				if len(urls) >= g.server.OCIDescriptorURLs {
					return store.ErrMetadataLimit
				}
				seen[locator] = true
				urls = append(urls, locator)
			}
			return nil
		}
		for _, child := range m.Children {
			if child.Kind != kind || child.Digest != expected.Digest {
				continue
			}
			if metadata.Descriptors[g.image+"/"+kind+"/"+child.Digest] != child.OCIDescriptor {
				return nil, errUpstreamIntegrity
			}
			if e = take(child.OCIDescriptor, child.URLs); e != nil {
				return nil, e
			}
		}
		if kind == "manifests" && m.Subject != nil && m.Subject.Digest == expected.Digest {
			if metadata.Subject == nil || *metadata.Subject != *m.Subject {
				return nil, errUpstreamIntegrity
			}
			if e = take(*m.Subject, m.SubjectURLs); e != nil {
				return nil, e
			}
		}
	}
	if len(urls) == 0 && kind == "manifests" {
		return g.retainedReferrerURLs(expected)
	}
	return urls, nil
}

// A referrers index is a mutable source advertisement, so do not persist its
// alternate URLs. Recover the canonical subject from verified cached referent
// bytes and walk that source index again when refreshing a direct referent pin.
func (g *ociGraphFill) retainedReferrerURLs(expected *store.OCIDescriptor) ([]string, error) {
	a, e := g.server.DB.CachedOCIObject(g.ctx, g.identity, g.repo.Name, g.image+"/manifests/"+expected.Digest)
	if errors.Is(e, store.ErrNotFound) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if a.Decision == "denied" {
		return nil, store.ErrDenied
	}
	if a.Size > ociManifestBytes || a.Size > g.server.NativeMetadataBytes-g.metadata {
		return nil, store.ErrMetadataLimit
	}
	input, e := g.server.Blobs.OpenVerified(g.ctx, g.identity.Tenant, a.Digest, a.Size)
	if e != nil {
		return nil, errUpstreamIntegrity
	}
	raw, e := io.ReadAll(io.LimitReader(input, ociManifestBytes+1))
	input.Close()
	if e != nil || len(raw) > ociManifestBytes {
		return nil, errUpstreamIntegrity
	}
	g.metadata += int64(len(raw))
	m, e := parseOCIManifest(raw, a.MediaType)
	var metadata store.OCIManifestMetadata
	if e != nil || json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated {
		return nil, errUpstreamIntegrity
	}
	if m.Subject == nil {
		return nil, nil
	}
	if metadata.Subject == nil || *metadata.Subject != *m.Subject || "sha256:"+a.Digest != expected.Digest || expected.Size >= 0 && (expected.Size != a.Size || expected.MediaType != a.MediaType) {
		return nil, errUpstreamIntegrity
	}
	*expected = store.OCIDescriptor{Digest: expected.Digest, Size: a.Size, MediaType: a.MediaType}
	path := g.image + "/referrers/" + m.Subject.Digest
	response, e := g.client.getCatalog(g.ctx, path, http.Header{"Accept": {ociIndexMediaType}})
	if e != nil {
		return nil, e
	}
	if response.StatusCode == 404 {
		response.Body.Close()
		path = g.image + "/manifests/" + strings.Replace(m.Subject.Digest, ":", "-", 1)
		response, e = g.client.getCatalog(g.ctx, path, http.Header{"Accept": {ociIndexMediaType}})
		if e != nil {
			return nil, e
		}
		if response.StatusCode == 404 {
			response.Body.Close()
			return nil, nil
		}
	}
	defer func() {
		if response != nil {
			response.Body.Close()
		}
	}()
	urls := []string{}
	seenPages, seenEntries := map[string]bool{}, map[string]bool{}
	for page := 0; page < g.server.OCICatalogPages; page++ {
		if response.Request == nil || response.Request.URL == nil || seenPages[response.Request.URL.String()] {
			return nil, upstream.ErrDestination
		}
		seenPages[response.Request.URL.String()] = true
		if e = g.response(response); e != nil {
			return nil, e
		}
		raw, e = io.ReadAll(io.LimitReader(response.Body, ociManifestBytes+1))
		response.Body.Close()
		g.metadata += int64(len(raw))
		g.bytes += int64(len(raw))
		if e != nil || len(raw) > ociManifestBytes || g.metadata > g.server.NativeMetadataBytes || g.bytes > g.server.OCIGraphBytes {
			return nil, store.ErrMetadataLimit
		}
		index, e := parseOCIManifest(raw, response.Header.Get("Content-Type"))
		if e != nil || index.MediaType != ociIndexMediaType {
			return nil, errUpstreamIntegrity
		}
		for _, child := range index.Children {
			if seenEntries[child.Digest] || len(seenEntries) >= g.server.NativeVersionLimit {
				return nil, store.ErrMetadataLimit
			}
			seenEntries[child.Digest] = true
			if child.Digest == expected.Digest {
				if child.OCIDescriptor != *expected {
					return nil, errUpstreamIntegrity
				}
				urls = child.URLs
			}
		}
		next, e := ociPageLocation(response, g.client.urlLimit)
		if e != nil {
			return nil, e
		}
		if next == "" {
			return urls, nil
		}
		if seenPages[next] || page+1 >= g.server.OCICatalogPages {
			return nil, store.ErrMetadataLimit
		}
		response, e = g.client.page(g.ctx, path, next, http.Header{"Accept": {ociIndexMediaType}})
		if e != nil {
			return nil, e
		}
	}
	return nil, store.ErrMetadataLimit
}

func (g *ociGraphFill) descriptorResponse(kind string, expected *store.OCIDescriptor, original *http.Response, urls []string) (*http.Response, error) {
	if original.StatusCode != 404 || g.server.OCIDescriptorURLs == 0 {
		return original, nil
	}
	if len(urls) == 0 {
		var e error
		urls, e = g.retainedDescriptor(kind, expected)
		if e != nil {
			original.Body.Close()
			return nil, e
		}
	}
	if len(urls) == 0 {
		return original, nil
	}
	original.Body.Close()
	// Metadata/signature integrity errors stop immediately. Only unavailable
	// candidates are tried elsewhere; a source authorization error is not absence.
	var failed error
	for _, raw := range urls {
		if g.descriptorTries >= g.server.OCIDescriptorURLs {
			return nil, store.ErrMetadataLimit
		}
		g.descriptorTries++
		target, parseError := url.Parse(raw)
		if parseError != nil || original.Request != nil && original.Request.URL != nil && original.Request.URL.Scheme == "https" && target.Scheme != "https" {
			failed = upstream.ErrDestination
			continue
		}
		selected, e := g.client.destination(raw)
		if e != nil || selected.RegistryDeliveryPriority(raw) == 0 {
			failed = upstream.ErrDestination
			continue
		}
		accept := "application/octet-stream"
		if kind == "manifests" {
			accept = ociManifestAccept
		}
		response, e := g.client.fetchURL(g.ctx, raw, http.Header{"Accept": {accept}}, "", false)
		if e != nil {
			return nil, e
		}
		response, e = g.client.follow(g.ctx, response, http.Header{"Accept": {accept}}, "", false)
		if e != nil {
			return nil, e
		}
		switch response.StatusCode {
		case 200:
			return response, nil
		case 404:
			response.Body.Close()
		default:
			e = g.response(response)
			response.Body.Close()
			if errors.Is(e, errOCITransient) {
				failed = e
				continue
			}
			return nil, e
		}
	}
	if failed != nil {
		return nil, failed
	}
	return original, nil
}
