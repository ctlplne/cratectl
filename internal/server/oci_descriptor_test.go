// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestOCIProxyFetchesApprovedDescriptorURLs(t *testing.T) {
	payload := []byte("{}")
	var hits atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer owned-descriptor-source" || r.Header.Get("Referer") != "" {
			t.Error("descriptor credential authority changed")
		}
		w.Write(payload)
	}))
	defer cdn.Close()
	document := ociFixture()
	document["config"].(map[string]any)["urls"] = []string{cdn.URL + "/objects/config"}
	raw, _ := json.Marshal(document)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/app/manifests/latest" {
			w.Header().Set("Content-Type", testOCIImage)
			w.Write(raw)
			return
		}
		w.WriteHeader(404)
	}))
	defer origin.Close()
	objects, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	api := New(nil, objects, "")
	api.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	api.UpstreamCredentials["test-a/descriptor"] = UpstreamCredential{Value: "owned-descriptor-source", AllowedURL: cdn.URL + "/objects/"}
	repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, DownloadSources: []upstream.Config{{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "descriptor"}}}}
	i := store.Identity{Tenant: "test-a"}
	client, e := api.newOCIRegistryClient(i, repo, "app")
	if e != nil {
		t.Fatal(e)
	}
	defer client.close()
	g := ociGraphFill{server: api, client: client, ctx: context.Background(), identity: i, repo: repo, image: "app", objects: map[string]store.Artifact{}, stack: map[string]bool{}}
	a, e := g.manifest("latest", nil, nil, 0)
	if e != nil || a.Digest != crypt.Digest(raw) || hits.Load() != 1 || len(g.objects) != 2 {
		t.Fatalf("approved descriptor URL graph failed: %v, hits=%d, objects=%d", e, hits.Load(), len(g.objects))
	}
}

func TestOCIDescriptorFallbackAuthorityIntegrityAndBudgets(t *testing.T) {
	for _, mode := range []string{"valid", "origin-present", "second-url", "temporary-url", "origin-forbidden", "corrupt", "size", "foreign", "network", "query-denied", "query-approved", "budget", "disabled", "downgrade"} {
		t.Run(mode, func(t *testing.T) {
			payload := []byte("descriptor exact bytes")
			var hits, foreignHits atomic.Int32
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
			defer foreign.Close()
			cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Header.Get("Authorization") != "Bearer owned-alternate" || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" {
					t.Error("descriptor request crossed credential authority")
				}
				switch r.URL.Path {
				case "/objects/missing":
					w.WriteHeader(404)
					return
				case "/objects/temporary":
					w.WriteHeader(503)
					return
				}
				if mode == "corrupt" {
					w.Write([]byte("wrong bytes same count"))
					return
				}
				w.Write(payload)
			}))
			defer cdn.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "origin-present" {
					w.Write(payload)
					return
				}
				if mode == "origin-forbidden" {
					w.WriteHeader(403)
					return
				}
				w.WriteHeader(404)
			}))
			defer origin.Close()
			objects, e := blob.New(t.TempDir(), 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			api := New(nil, objects, "")
			api.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			api.UpstreamCredentials["test-a/alternate"] = UpstreamCredential{Value: "owned-alternate", AllowedURL: cdn.URL + "/objects/"}
			if mode == "network" {
				api.PrivateUpstreamNetworks = nil
			}
			if mode == "budget" {
				api.OCIDescriptorURLs = 1
			}
			if mode == "disabled" {
				api.OCIDescriptorURLs = 0
			}
			repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, DownloadSources: []upstream.Config{{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "alternate", AllowSignedQuery: mode == "query-approved"}}}}
			i := store.Identity{Tenant: "test-a"}
			client, e := api.newOCIRegistryClient(i, repo, "app")
			if e != nil {
				t.Fatal(e)
			}
			defer client.close()
			urls := []string{cdn.URL + "/objects/valid"}
			switch mode {
			case "second-url", "budget":
				urls = append([]string{cdn.URL + "/objects/missing"}, urls...)
			case "temporary-url":
				urls = append([]string{cdn.URL + "/objects/temporary"}, urls...)
			case "foreign":
				urls = []string{foreign.URL + "/objects/valid"}
			case "query-denied", "query-approved":
				urls[0] += "?proof=owned%2Fquery&order=two&order=one"
			case "corrupt":
				urls = append(urls, cdn.URL+"/objects/other")
			}
			d := store.OCIDescriptor{Digest: "sha256:" + crypt.Digest(payload), Size: int64(len(payload)), MediaType: "text/plain"}
			if mode == "size" {
				d.Size++
			}
			g := ociGraphFill{server: api, client: client, ctx: context.Background(), identity: i, repo: repo, image: "app", objects: map[string]store.Artifact{}, stack: map[string]bool{}}
			var provided *http.Response
			if mode == "downgrade" {
				r, _ := http.NewRequest("GET", "https://registry.example/v2/app/blobs/"+d.Digest, nil)
				provided = &http.Response{StatusCode: 404, Body: http.NoBody, Request: r}
			}
			a, e := g.blob(d, provided, urls...)
			good := mode == "valid" || mode == "origin-present" || mode == "second-url" || mode == "temporary-url" || mode == "query-approved"
			if good {
				if e != nil || a.Digest != crypt.Digest(payload) {
					t.Fatalf("valid fallback failed: %v", e)
				}
			} else if e == nil || len(g.objects) != 0 {
				t.Fatal("invalid descriptor fallback published bytes")
			}
			if foreignHits.Load() != 0 {
				t.Fatal("unapproved URI received a request")
			}
			if (mode == "origin-present" || mode == "origin-forbidden" || mode == "foreign" || mode == "query-denied" || mode == "disabled" || mode == "downgrade") && hits.Load() != 0 {
				t.Fatal("fallback crossed a forbidden boundary")
			}
			if (mode == "corrupt" || mode == "budget") && hits.Load() != 1 {
				t.Fatal("failure or budget continued into another locator")
			}
		})
	}
}

func TestOCIDescriptorURLParserBoundsAndNormalization(t *testing.T) {
	for _, bad := range []any{nil, []any{nil}, []string{"not-absolute"}, []string{"https://example/\nsecret"}, []string{"https://example/" + strings.Repeat("a", 32<<10)}, make([]string, 65)} {
		fixture := ociFixture()
		fixture["config"].(map[string]any)["urls"] = bad
		raw, _ := json.Marshal(fixture)
		if _, e := parseOCIManifest(raw, testOCIImage); e == nil {
			t.Fatal("invalid or unbounded descriptor locator accepted")
		}
	}
	fixture := ociFixture()
	fixture["config"].(map[string]any)["urls"] = []string{"https://delivery.example/objects/config?signature=opaque"}
	raw, _ := json.Marshal(fixture)
	parsed, e := parseOCIManifest(raw, testOCIImage)
	if e != nil || len(parsed.Children[0].URLs) != 1 {
		t.Fatal("valid locator lost before intake", e)
	}
	metadata, _ := json.Marshal(parsed.metadata("app"))
	if strings.Contains(string(metadata), "signature=opaque") {
		t.Fatal("ephemeral descriptor locator copied into normalized metadata")
	}
}
