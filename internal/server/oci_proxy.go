// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

var errOCIOriginMissing = errors.New("OCI origin coordinate is missing")
var errOCITransient = errors.New("temporary OCI origin failure")

type ociGraphFill struct {
	server          *Server
	client          *ociRegistryClient
	ctx             context.Context
	identity        store.Identity
	repo            store.Repository
	image           string
	objects         map[string]store.Artifact
	stack           map[string]bool
	bytes, metadata int64
	fresh, stale    int
	memberCaches    map[string]store.OCIMemberCache
	rootResponse    *http.Response
	rootCache       *store.OCIMemberCache
}

func (g *ociGraphFill) remember(path string, response *http.Response) error {
	if g.memberCaches == nil {
		g.memberCaches = map[string]store.OCIMemberCache{}
	}
	fresh, stale, e := cachePolicy(response.Header, g.repo, store.Retrieval{}, 200)
	if e != nil {
		return e
	}
	c := store.OCIMemberCache{ETag: response.Header.Get("ETag"), Modified: response.Header.Get("Last-Modified"), FreshSeconds: fresh, StaleSeconds: stale}
	if response == g.rootResponse && g.rootCache != nil {
		c = *g.rootCache
	}
	if len(c.ETag) > 1024 || len(c.Modified) > 128 {
		return store.ErrMetadataLimit
	}
	g.memberCaches[path] = c
	return nil
}

func (g *ociGraphFill) response(response *http.Response) error {
	if response.StatusCode == 404 {
		return errOCIOriginMissing
	}
	if response.StatusCode != 200 {
		if response.StatusCode >= 500 {
			return errOCITransient
		}
		return errUpstream
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return errUpstreamIntegrity
	}
	fresh, stale, e := cachePolicy(response.Header, g.repo, store.Retrieval{}, 200)
	if e != nil {
		return e
	}
	g.fresh = min(g.fresh, fresh)
	g.stale = min(g.stale, stale)
	return nil
}
func (g *ociGraphFill) blob(d store.OCIDescriptor, provided ...*http.Response) (store.Artifact, error) {
	p := g.image + "/blobs/" + d.Digest
	if a, ok := g.objects[p]; ok {
		if d.Size >= 0 && a.Size != d.Size {
			return a, errUpstreamIntegrity
		}
		return a, nil
	}
	if len(g.objects) >= 4095 || d.Size > g.server.OCIGraphBytes-g.bytes {
		return store.Artifact{}, store.ErrMetadataLimit
	}
	var response *http.Response
	var e error
	if len(provided) > 0 {
		response = provided[0]
	} else {
		response, e = g.client.get(g.ctx, p, nil, nil)
	}
	if e != nil {
		return store.Artifact{}, e
	}
	defer response.Body.Close()
	if e = g.response(response); e != nil {
		return store.Artifact{}, e
	}
	if d.Size >= 0 && response.ContentLength >= 0 && response.ContentLength != d.Size {
		return store.Artifact{}, errUpstreamIntegrity
	}
	length := d.Size
	if length < 0 {
		length = response.ContentLength
	}
	object, e := g.server.Blobs.Put(g.ctx, g.identity.Tenant, io.LimitReader(response.Body, g.server.OCIGraphBytes-g.bytes+1), strings.TrimPrefix(d.Digest, "sha256:"), length)
	if e != nil {
		return store.Artifact{}, errUpstreamIntegrity
	}
	g.bytes += object.Size
	if g.bytes > g.server.OCIGraphBytes {
		return store.Artifact{}, store.ErrMetadataLimit
	}
	a := store.Artifact{Path: p, Digest: object.Digest, Size: object.Size, MediaType: "application/octet-stream"}
	if e = g.remember(p, response); e != nil {
		return store.Artifact{}, e
	}
	g.objects[p] = a
	return a, nil
}
func (g *ociGraphFill) manifest(ref string, d *store.OCIDescriptor, response *http.Response, depth int) (store.Artifact, error) {
	p := g.image + "/manifests/" + ref
	if a, ok := g.objects[p]; ok {
		if d != nil && (a.Size != d.Size || a.MediaType != d.MediaType) {
			return a, errUpstreamIntegrity
		}
		return a, nil
	}
	if depth >= 32 || len(g.objects) >= 4096 || g.stack[p] {
		return store.Artifact{}, store.ErrMetadataLimit
	}
	g.stack[p] = true
	defer delete(g.stack, p)
	var e error
	if response == nil {
		response, e = g.client.get(g.ctx, p, nil, http.Header{"Accept": {ociManifestAccept}})
		if e != nil {
			return store.Artifact{}, e
		}
	}
	defer response.Body.Close()
	if e = g.response(response); e != nil {
		return store.Artifact{}, e
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, ociManifestBytes+1))
	if e != nil || len(data) > ociManifestBytes {
		return store.Artifact{}, store.ErrMetadataLimit
	}
	digest := "sha256:" + crypt.Digest(data)
	if (ociDigest.MatchString(ref) && ref != digest) || (d != nil && (d.Digest != digest || d.Size != int64(len(data)))) {
		return store.Artifact{}, errUpstreamIntegrity
	}
	if header := response.Header.Get("Docker-Content-Digest"); header != "" && header != digest {
		return store.Artifact{}, errUpstreamIntegrity
	}
	m, e := parseOCIManifest(data, response.Header.Get("Content-Type"))
	if e != nil {
		return store.Artifact{}, errUpstreamIntegrity
	}
	if d != nil && m.MediaType != d.MediaType {
		return store.Artifact{}, errUpstreamIntegrity
	}
	g.bytes += int64(len(data))
	if g.bytes > g.server.OCIGraphBytes {
		return store.Artifact{}, store.ErrMetadataLimit
	}
	if a, ok := g.objects[g.image+"/manifests/"+digest]; ok {
		if a.Size != int64(len(data)) || a.MediaType != m.MediaType {
			return a, errUpstreamIntegrity
		}
		return a, nil
	}
	g.metadata += int64(len(data))
	if g.metadata > g.server.NativeMetadataBytes {
		return store.Artifact{}, store.ErrMetadataLimit
	}
	if m.Subject != nil {
		if _, e = g.manifest(m.Subject.Digest, m.Subject, nil, depth+1); e != nil && !errors.Is(e, errOCIOriginMissing) {
			return store.Artifact{}, e
		}
	}
	for _, child := range m.Children {
		if child.Kind == "manifests" {
			_, e = g.manifest(child.Digest, &child.OCIDescriptor, nil, depth+1)
		} else {
			_, e = g.blob(child.OCIDescriptor)
		}
		if e != nil {
			return store.Artifact{}, e
		}
	}
	object, e := g.server.Blobs.Put(g.ctx, g.identity.Tenant, bytes.NewReader(data), strings.TrimPrefix(digest, "sha256:"), int64(len(data)))
	if e != nil {
		return store.Artifact{}, e
	}
	metadata, _ := json.Marshal(m.metadata(g.image))
	a := store.Artifact{Path: g.image + "/manifests/" + digest, Digest: object.Digest, Size: object.Size, MediaType: m.MediaType, Metadata: metadata}
	if e = g.remember(a.Path, response); e != nil {
		return store.Artifact{}, e
	}
	g.objects[a.Path] = a
	return a, nil
}

const ociManifestAccept = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json"

func (s *Server) fillOCIProxy(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	result := store.RetrievalResult{FreshSeconds: repo.Settings.Cache.NegativeSeconds}
	image, kind, ref := parseOCIPath(lease.Path)
	catalog := false
	if strings.HasPrefix(lease.Path, "oci-catalog/") {
		catalog = true
		path := strings.TrimPrefix(lease.Path, "oci-catalog/")
		if strings.HasSuffix(path, "/tags") {
			image, kind = strings.TrimSuffix(path, "/tags"), "tags/list"
		} else {
			n := strings.LastIndex(path, "/referrers/")
			if n < 1 {
				return store.ErrConflict
			}
			image, kind, ref = path[:n], "referrers", path[n+len("/referrers/"):]
		}
	}
	if !ociImage.MatchString(image) {
		return store.ErrConflict
	}
	client, e := s.newOCIRegistryClient(i, repo, image)
	if e != nil {
		result.Failure = "upstream_authority_failure"
	} else {
		defer client.close()
		validators := http.Header{}
		if lease.ETag != "" {
			validators.Set("If-None-Match", lease.ETag)
		}
		if lease.Modified != "" {
			validators.Set("If-Modified-Since", lease.Modified)
		}
		// A mutable manifest pointer needs byte identity, rather than semantic
		// equivalence or a one-second timestamp, before reusing its exact digest.
		if kind == "manifests" {
			if strings.HasPrefix(strings.TrimSpace(lease.ETag), "W/") {
				validators.Del("If-None-Match")
			}
			validators.Del("If-Modified-Since")
		}
		validators.Set("Accept", ociManifestAccept)
		if kind == "tags/list" {
			validators.Set("Accept", "application/json")
		} else if kind == "blobs" {
			validators.Set("Accept", "application/octet-stream")
		}
		requestPath := image + "/" + kind
		if ref != "" {
			requestPath += "/" + ref
		}
		response, err := client.get(ctx, requestPath, nil, validators)
		e = err
		if e == nil {
			defer response.Body.Close()
			result.Status = response.StatusCode
			switch result.Status {
			case 200, 304:
				result.FreshSeconds, result.StaleSeconds, e = cachePolicy(response.Header, repo, lease, result.Status)
				if e != nil {
					result.Failure = "upstream_cache_policy_failure"
					break
				}
				result.ETag, result.Modified = response.Header.Get("ETag"), response.Header.Get("Last-Modified")
				if len(result.ETag) > 1024 || len(result.Modified) > 128 {
					result.Failure = "upstream_header_limit"
					break
				}
				var rootCache *store.OCIMemberCache
				if result.Status == 304 {
					if validators.Get("If-None-Match") == "" && validators.Get("If-Modified-Since") == "" {
						e = errUpstreamIntegrity
						break
					}
					if kind == "manifests" && result.ETag != "" && result.ETag != validators.Get("If-None-Match") {
						e = errUpstreamIntegrity
						break
					}
					if kind == "blobs" {
						break
					}
					cached, err := s.DB.CachedOCIObject(ctx, i, repo.Name, lease.Path)
					if err != nil {
						e = err
						break
					}
					header := response.Header.Clone()
					header.Set("Content-Type", cached.MediaType)
					var body io.ReadCloser
					if catalog {
						var c store.OCICatalog
						if json.Unmarshal(cached.Metadata, &c) != nil {
							e = store.ErrConflict
							break
						}
						var data []byte
						if kind == "tags/list" {
							names := []string{}
							for tag := range c.Tags {
								names = append(names, tag)
							}
							sort.Strings(names)
							data, _ = json.Marshal(map[string]any{"name": upstreamOCIImage(repo, image), "tags": names})
							header.Set("Content-Type", "application/json")
						} else {
							data, _ = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": c.Referrers})
							header.Set("Content-Type", "application/vnd.oci.image.index.v1+json")
						}
						body = io.NopCloser(bytes.NewReader(data))
					} else {
						body, err = s.Blobs.OpenVerified(ctx, i.Tenant, cached.Digest, cached.Size)
						if err != nil {
							e = err
							break
						}
					}
					response = &http.Response{StatusCode: 200, Header: header, Body: body, Request: response.Request, ContentLength: -1}
					defer body.Close()
					rootCache = &store.OCIMemberCache{ETag: lease.ETag, Modified: lease.Modified, FreshSeconds: result.FreshSeconds, StaleSeconds: result.StaleSeconds}
				}
				g := ociGraphFill{server: s, client: client, ctx: ctx, identity: i, repo: repo, image: image, objects: map[string]store.Artifact{}, stack: map[string]bool{}, fresh: result.FreshSeconds, stale: result.StaleSeconds}
				g.rootResponse = response
				g.rootCache = rootCache
				publication := &store.OCIPublication{Image: image, Tags: map[string]string{}}
				var root store.Artifact
				if catalog {
					var index store.OCICatalog
					index, e = g.catalog(kind, ref, response)
					if e == nil {
						data, _ := json.Marshal(index)
						var object blob.Object
						object, e = s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), "", int64(len(data)))
						result.Object = &object
						result.Metadata = data
						result.MediaType = store.OCICatalogMedia
						publication.Tags = index.Tags
						publication.CompleteTags = kind == "tags/list"
					}
				} else if kind == "manifests" {
					root, e = g.manifest(ref, nil, response, 0)
					if e == nil {
						publication.Reference = ref
						if !ociDigest.MatchString(ref) {
							publication.Tags[ref] = "sha256:" + root.Digest
						}
						result.Object = &blob.Object{Digest: root.Digest, Size: root.Size}
						result.Metadata = root.Metadata
						result.MediaType = root.MediaType
					}
				} else if kind == "blobs" {
					root, e = g.blob(store.OCIDescriptor{Digest: ref, Size: -1}, response)
					if e == nil {
						result.Object = &blob.Object{Digest: root.Digest, Size: root.Size}
						result.Metadata = root.Metadata
						result.MediaType = root.MediaType
					}
				} else {
					e = store.ErrConflict
				}
				if e == nil {
					result.FreshSeconds, result.StaleSeconds = g.fresh, g.stale
					for _, a := range g.objects {
						publication.Objects = append(publication.Objects, a)
					}
					sort.Slice(publication.Objects, func(a, b int) bool { return publication.Objects[a].Path < publication.Objects[b].Path })
					result.OCI = publication
					publication.MemberCaches = g.memberCaches
					if kind == "tags/list" && response.Header.Get("Link") != "" {
						result.ETag = ""
						result.Modified = ""
					}
				}
			case 404:
				negative := repo
				negative.Settings.Cache.FreshSeconds = repo.Settings.Cache.NegativeSeconds
				result.FreshSeconds, _, e = cachePolicy(response.Header, negative, lease, 404)
			default:
				result.Failure = "upstream_rejected_request"
				if result.Status >= 500 {
					result.Failure = "transient_upstream_failure"
				}
			}
		}
	}
	if e != nil && result.Failure == "" {
		result.Failure = "upstream_graph_failure"
		if errors.Is(e, upstream.ErrDestination) || errors.Is(e, upstream.ErrRedirect) || errors.Is(e, upstream.ErrPath) {
			result.Failure = "upstream_authority_failure"
		}
		if errors.Is(e, errUpstreamIntegrity) {
			result.Failure = "upstream_integrity_failure"
		}
		if errors.Is(e, errOCITransient) {
			result.Failure = "transient_upstream_failure"
		}
	}
	if ctx.Err() != nil {
		result.Failure = "retrieval_cancelled"
	}
	if result.Failure != "" {
		result.Object = nil
		result.OCI = nil
	}
	completion := ctx
	var done context.CancelFunc
	if ctx.Err() != nil {
		completion, done = context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer done()
	}
	err := s.DB.CompleteRetrieval(completion, i, lease, result)
	if err != nil && result.OCI != nil && !errors.Is(err, store.ErrLeaseLost) {
		failure := store.RetrievalResult{Status: result.Status, Failure: "upstream_graph_publication_rejected"}
		if cleanup := s.DB.CompleteRetrieval(completion, i, lease, failure); cleanup != nil {
			return cleanup
		}
	}
	return err
}

func (g *ociGraphFill) catalog(kind, subject string, response *http.Response) (store.OCICatalog, error) {
	catalog := store.OCICatalog{Image: g.image}
	if kind == "tags/list" {
		catalog.Tags = map[string]string{}
		seen := map[string]bool{}
		for page := 0; page < 32; page++ {
			if e := g.response(response); e != nil {
				return catalog, e
			}
			data, e := io.ReadAll(io.LimitReader(response.Body, g.server.NativeMetadataBytes+1))
			response.Body.Close()
			g.metadata += int64(len(data))
			g.bytes += int64(len(data))
			if g.metadata > g.server.NativeMetadataBytes || g.bytes > g.server.OCIGraphBytes {
				return catalog, store.ErrMetadataLimit
			}
			if e != nil || int64(len(data)) > g.server.NativeMetadataBytes || uniqueOCIJSON(data) != nil {
				return catalog, store.ErrMetadataLimit
			}
			var index struct {
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			}
			if json.Unmarshal(data, &index) != nil || index.Name != upstreamOCIImage(g.repo, g.image) {
				return catalog, errUpstreamIntegrity
			}
			for _, tag := range index.Tags {
				if !ociTag.MatchString(tag) || seen[tag] || len(seen) >= g.server.NativeTagLimit {
					return catalog, store.ErrMetadataLimit
				}
				seen[tag] = true
				a, e := g.manifest(tag, nil, nil, 0)
				if e != nil {
					return catalog, e
				}
				catalog.Tags[tag] = "sha256:" + a.Digest
			}
			link := response.Header.Get("Link")
			if link == "" {
				return catalog, nil
			}
			next, e := ociNextPage(response, link)
			if e != nil {
				return catalog, e
			}
			response, e = g.client.get(g.ctx, g.image+"/tags/list", next, nil)
			if e != nil {
				return catalog, e
			}
		}
		response.Body.Close()
		return catalog, store.ErrMetadataLimit
	}
	if e := g.response(response); e != nil {
		return catalog, e
	}
	// Referrer pagination is not implemented yet. A partial index must never
	// masquerade as a complete, durably cached discovery result.
	if response.Header.Get("Link") != "" {
		return catalog, store.ErrMetadataLimit
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, ociManifestBytes+1))
	g.metadata += int64(len(data))
	g.bytes += int64(len(data))
	if g.metadata > g.server.NativeMetadataBytes || g.bytes > g.server.OCIGraphBytes {
		return catalog, store.ErrMetadataLimit
	}
	if e != nil || len(data) > ociManifestBytes {
		return catalog, store.ErrMetadataLimit
	}
	m, e := parseOCIManifest(data, response.Header.Get("Content-Type"))
	if e != nil || m.MediaType != "application/vnd.oci.image.index.v1+json" {
		return catalog, errUpstreamIntegrity
	}
	catalog.Subject = subject
	catalog.Referrers = []store.OCIReferrer{}
	for _, d := range m.Children {
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
	if _, e = g.manifest(subject, nil, nil, 0); e != nil && !errors.Is(e, errOCIOriginMissing) {
		return catalog, e
	}
	return catalog, nil
}

func ociNextPage(response *http.Response, link string) (url.Values, error) {
	if len(link) > 4096 || strings.Contains(link, ",") {
		return nil, upstream.ErrDestination
	}
	left, rest, ok := strings.Cut(link, ">")
	_, parameters, parameterErr := mime.ParseMediaType("application/octet-stream" + rest)
	if !ok || !strings.HasPrefix(left, "<") || parameterErr != nil || parameters["rel"] != "next" {
		return nil, upstream.ErrDestination
	}
	next, e := url.Parse(strings.TrimPrefix(left, "<"))
	if e != nil {
		return nil, upstream.ErrDestination
	}
	next = response.Request.URL.ResolveReference(next)
	current := response.Request.URL
	if next.Scheme != current.Scheme || next.Host != current.Host || next.Path != current.Path || next.RawPath != "" || next.User != nil || next.Fragment != "" {
		return nil, upstream.ErrDestination
	}
	values, e := url.ParseQuery(next.RawQuery)
	if e != nil || values.Get("last") == "" {
		return nil, upstream.ErrDestination
	}
	return values, nil
}
