// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

// A Link list can contain commas inside URI references and quoted parameters.
// Bound and parse all entries before choosing exactly one next relation.
func ociNextLink(values []string, urlBytes int) (string, error) {
	next := ""
	total, entries := 0, 0
	for _, value := range values {
		total += len(value)
		if total > 32<<10 {
			return "", upstream.ErrDestination
		}
		begin := 0
		angle, quoted, escaped := false, false, false
		consume := func(part string) error {
			entries++
			if entries > 64 {
				return upstream.ErrDestination
			}
			part = strings.TrimSpace(part)
			uri, rest, ok := strings.Cut(part, ">")
			if !ok || !strings.HasPrefix(uri, "<") || len(uri) <= 1 || len(uri)-1 > urlBytes {
				return upstream.ErrDestination
			}
			_, params, e := mime.ParseMediaType("application/octet-stream" + rest)
			if e != nil {
				return upstream.ErrDestination
			}
			for _, rel := range strings.Fields(params["rel"]) {
				if strings.EqualFold(rel, "next") {
					if next != "" || params["anchor"] != "" {
						return upstream.ErrDestination
					}
					next = uri[1:]
				}
			}
			return nil
		}
		for n, c := range value {
			if angle {
				if c == '>' {
					angle = false
				}
				continue
			}
			if quoted {
				if escaped {
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == '"' {
					quoted = false
				}
				continue
			}
			switch c {
			case '<':
				angle = true
			case '"':
				quoted = true
			case ',':
				if e := consume(value[begin:n]); e != nil {
					return "", e
				}
				begin = n + 1
			}
		}
		if angle || quoted || escaped {
			return "", upstream.ErrDestination
		}
		if e := consume(value[begin:]); e != nil {
			return "", e
		}
	}
	return next, nil
}
func ociPageLocation(response *http.Response, urlBytes int) (string, error) {
	raw, e := ociNextLink(response.Header.Values("Link"), urlBytes)
	if e != nil || raw == "" {
		return "", e
	}
	link := &http.Response{Request: response.Request, Header: http.Header{"Location": {raw}}}
	return ociDeliveryLocation(link, 0, 1, urlBytes)
}

func (g *ociGraphFill) catalog(kind, subject string, response *http.Response) (store.OCICatalog, error) {
	catalog := store.OCICatalog{Image: g.image}
	path := g.image + "/" + kind
	if kind == "tags/list" {
		catalog.Tags = map[string]string{}
	} else {
		catalog.Subject = subject
		catalog.Referrers = []store.OCIReferrer{}
		path += "/" + subject
	}
	if g.catalogPath != "" {
		path = g.catalogPath
	}
	seenEntries := map[string]bool{}
	seenPages := map[string]bool{}
	defer func() {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
	}()
	for page := 0; page < g.server.OCICatalogPages; page++ {
		if response.Request == nil || response.Request.URL == nil {
			return catalog, upstream.ErrDestination
		}
		uri := response.Request.URL.String()
		if seenPages[uri] {
			return catalog, upstream.ErrDestination
		}
		seenPages[uri] = true
		if e := g.response(response); e != nil {
			return catalog, e
		}
		bound := g.server.NativeMetadataBytes
		if kind != "tags/list" {
			bound = min(bound, int64(ociManifestBytes))
		}
		data, e := io.ReadAll(io.LimitReader(response.Body, bound+1))
		response.Body.Close()
		g.metadata += int64(len(data))
		g.bytes += int64(len(data))
		if e != nil || int64(len(data)) > bound || g.metadata > g.server.NativeMetadataBytes || g.bytes > g.server.OCIGraphBytes {
			return catalog, store.ErrMetadataLimit
		}
		if kind == "tags/list" {
			var index struct {
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			}
			if uniqueOCIJSON(data) != nil || json.Unmarshal(data, &index) != nil || index.Name != upstreamOCIImage(g.repo, g.image) {
				return catalog, errUpstreamIntegrity
			}
			for _, tag := range index.Tags {
				if !ociTag.MatchString(tag) || seenEntries[tag] || len(seenEntries) >= g.server.NativeTagLimit {
					return catalog, store.ErrMetadataLimit
				}
				seenEntries[tag] = true
				a, e := g.manifest(tag, nil, nil, 0)
				if e != nil {
					return catalog, e
				}
				catalog.Tags[tag] = "sha256:" + a.Digest
			}
		} else {
			m, e := parseOCIManifest(data, response.Header.Get("Content-Type"))
			if e != nil || m.MediaType != ociIndexMediaType {
				return catalog, errUpstreamIntegrity
			}
			for _, d := range m.Children {
				if seenEntries[d.Digest] || len(seenEntries) >= g.server.NativeVersionLimit {
					return catalog, store.ErrMetadataLimit
				}
				seenEntries[d.Digest] = true
				a, e := g.manifest(d.Digest, &d.OCIDescriptor, nil, 0)
				if e != nil {
					return catalog, e
				}
				var metadata store.OCIManifestMetadata
				if json.Unmarshal(a.Metadata, &metadata) != nil || metadata.Subject == nil || metadata.Subject.Digest != subject {
					return catalog, errUpstreamIntegrity
				}
				catalog.Referrers = append(catalog.Referrers, store.OCIReferrer{OCIDescriptor: store.OCIDescriptor{MediaType: a.MediaType, Digest: "sha256:" + a.Digest, Size: a.Size}, ArtifactType: metadata.ArtifactType, Annotations: metadata.Annotations})
			}
		}
		next, e := ociPageLocation(response, g.client.urlLimit)
		if e != nil {
			return catalog, e
		}
		if next == "" {
			if kind != "tags/list" {
				if _, e = g.manifest(subject, nil, nil, 0); e != nil && !errors.Is(e, errOCIOriginMissing) {
					return catalog, e
				}
			}
			return catalog, nil
		}
		if seenPages[next] || page+1 >= g.server.OCICatalogPages {
			return catalog, store.ErrMetadataLimit
		}
		accept := ociManifestAccept
		if kind == "tags/list" {
			accept = "application/json"
		}
		response, e = g.client.page(g.ctx, path, next, http.Header{"Accept": {accept}})
		if e != nil {
			return catalog, e
		}
	}
	return catalog, store.ErrMetadataLimit
}

const ociIndexMediaType = "application/vnd.oci.image.index.v1+json"
