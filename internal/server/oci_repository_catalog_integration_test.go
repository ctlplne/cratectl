//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testnet"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestOCIRepositoryCatalogUsesCurrentGraphPolicyAndTenantGrants(t *testing.T) {
	s, db, token, admin := schemaServer(t)
	const endpoint = "/v2/_catalog"
	const public = "cratectl-catalog"
	const restricted = "cratectl-catalog-private"
	const manifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`
	configure := func(auth string, repo store.Repository) {
		t.Helper()
		w := lifecycleHTTP(t, s, auth)(http.MethodPost, "/api/v1/repositories", repo, "create-"+repo.Name)
		if w.Code != http.StatusCreated {
			t.Fatal("create", w.Code, w.Body.String())
		}
	}
	provision := func(tenant, actor, role string) string {
		t.Helper()
		credential, err := crypt.Token()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Provision(t.Context(), db.OwnerDSN, tenant, actor, role, credential, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		return credential
	}
	reader := provision(admin.Tenant, "cratectl-catalog-reader", "reader")
	other := provision("cratectl-catalog-other", "cratectl-operator", "admin")
	configure(token, store.Repository{Name: public, Format: "oci"})
	configure(token, store.Repository{Name: restricted, Format: "oci", Access: "restricted", RequireReview: true})
	configure(other, store.Repository{Name: public, Format: "oci"})

	put := func(auth, repo, image, ref, body string) string {
		t.Helper()
		w := mavenHTTP(t, s, auth, http.MethodPut, "/v2/"+repo+"/"+image+"/manifests/"+ref, body, "Content-Type", testOCIIndex)
		if w.Code != http.StatusCreated {
			t.Fatal("manifest publication", w.Code, w.Body.String())
		}
		return crypt.Digest([]byte(body))
	}
	leaf := put(token, public, "nested/app", "first", manifest)
	put(token, public, "nested/app", "second", strings.TrimSuffix(manifest, "}")+`,"annotations":{"description":"alternate"}}`)
	put(token, public, "z", "sha256:"+leaf, manifest)
	put(token, restricted, "nested/app", "first", manifest)
	root := strings.Replace(manifest, `[]`, fmt.Sprintf(`[{"mediaType":%q,"digest":%q,"size":%d}]`, testOCIIndex, "sha256:"+leaf, len(manifest)), 1)
	index := put(token, restricted, "nested/app", "index", root)
	put(other, public, "nested/app", "first", strings.TrimSuffix(manifest, "}")+`,"annotations":{"description":"second tenant"}}`)
	put(other, public, "private-to-other", "latest", manifest)
	request := func(auth, method, path string) *httptest.ResponseRecorder {
		t.Helper()
		return mavenHTTP(t, s, auth, method, path, "")
	}
	list := func(auth, path string, want ...string) string {
		t.Helper()
		w := request(auth, http.MethodGet, path)
		var body struct{ Repositories []string }
		if w.Code != http.StatusOK || w.Header().Get("Docker-Distribution-Api-Version") != "registry/2.0" ||
			w.Header().Get("Cache-Control") != "private, no-store" || json.Unmarshal(w.Body.Bytes(), &body) != nil ||
			body.Repositories == nil || !slices.Equal(body.Repositories, want) {
			t.Fatalf("catalog %s: status %d, body %s, expected %v", path, w.Code, w.Body.String(), want)
		}
		return w.Header().Get("Link")
	}
	if w := request("", http.MethodGet, endpoint); w.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated catalog", w.Code)
	}
	if w := request(reader, http.MethodPost, endpoint); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("catalog method guard", w.Code, w.Header())
	}
	for _, query := range []string{"n=-1", "n=1&n=2", "last=../outside", "last=cratectl-catalog%2F", "n=" + strings.Repeat("0", 1025)} {
		if w := request(reader, http.MethodGet, endpoint+"?"+query); w.Code != http.StatusBadRequest {
			t.Fatal("invalid pagination", w.Code)
		}
	}
	if list(reader, endpoint+"?n=0") != "" {
		t.Fatal("zero page returned a continuation")
	}
	link := list(reader, endpoint+"?n=1", public+"/nested/app")
	next, found := strings.CutPrefix(link, "<")
	next, complete := strings.CutSuffix(next, `>; rel="next"`)
	if !found || !complete || next != endpoint+"?last=cratectl-catalog%2Fnested%2Fapp&n=1" {
		t.Fatal("unexpected continuation", link)
	}
	if list(reader, next, public+"/z") != "" {
		t.Fatal("catalog continued after last page")
	}
	if w := request(reader, http.MethodHead, endpoint); w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("ETag") == "" {
		t.Fatal("catalog HEAD", w.Code, w.Header())
	}
	list(other, endpoint, public+"/nested/app", public+"/private-to-other")
	api := lifecycleHTTP(t, s, token)
	grant := func(allow bool, phase string) {
		t.Helper()
		if w := api(http.MethodPut, "/api/v1/repositories/"+restricted+"/grants",
			map[string]any{"actor": "cratectl-catalog-reader", "read": allow, "write": false}, phase); w.Code != http.StatusOK {
			t.Fatal("grant", w.Code, w.Body.String())
		}
	}
	decision := func(digest, value, key string) {
		t.Helper()
		if w := api(http.MethodPut, "/api/v1/repositories/"+restricted+"/decisions", map[string]string{
			"path": "nested/app/manifests/sha256:" + digest, "digest": digest, "decision": value,
		}, key); w.Code != http.StatusOK {
			t.Fatal("decision", w.Code, w.Body.String())
		}
	}
	grant(true, "grant-catalog-reader")
	decision(index, "allowed", "approve-catalog-index")
	list(reader, endpoint, public+"/nested/app", public+"/z")
	decision(leaf, "allowed", "approve-catalog-child")
	list(reader, endpoint, restricted+"/nested/app", public+"/nested/app", public+"/z")
	decision(leaf, "denied", "deny-catalog-child")
	list(reader, endpoint, public+"/nested/app", public+"/z")
	decision(leaf, "allowed", "restore-catalog-child")
	grant(false, "revoke-catalog-reader")
	list(reader, endpoint, public+"/nested/app", public+"/z")
	if w := request(token, http.MethodDelete, "/v2/"+public+"/z/manifests/sha256:"+leaf); w.Code != http.StatusAccepted {
		t.Fatal("retire digest-only manifest", w.Code, w.Body.String())
	}
	list(reader, endpoint, public+"/nested/app")
}

func TestOCIRepositoryCatalogUsesOnlyFreshCachedGraphs(t *testing.T) {
	s, _, token, _ := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	const child = `{}`
	const configMedia = "application/vnd.oci.image.config.v1+json"
	childDigest := "sha256:" + crypt.Digest([]byte(child))
	root := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"digest":%q,"size":%d},"layers":[]}`,
		testOCIImage, configMedia, childDigest, len(child))
	rootDigest := "sha256:" + crypt.Digest([]byte(root))
	const repo = "cratectl-catalog-cached"
	const image = "cached/app"
	const base = "/v2/cratectl-catalog-origin/" + image + "/"
	var requests atomic.Int64
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var document, digest, media string
		switch r.URL.Path {
		case base + "manifests/" + rootDigest, base + "manifests/latest":
			document, digest, media = root, rootDigest, testOCIImage
		case base + "blobs/" + childDigest:
			document, digest, media = child, childDigest, configMedia
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "max-age=90")
		w.Header().Set("Content-Type", media)
		w.Header().Set("Docker-Content-Digest", digest)
		_, _ = w.Write([]byte(document))
	})}}
	origin.Start()
	defer origin.Close()
	admin := lifecycleHTTP(t, s, token)
	proxy := store.Repository{Name: repo, Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{
		Upstream: &upstream.Config{URL: origin.URL + "/v2/cratectl-catalog-origin/", Networks: []string{"127.0.0.1/32"}},
		Cache:    store.CacheSettings{FreshSeconds: 90, NegativeSeconds: 30},
	}}
	if w := admin(http.MethodPost, "/api/v1/repositories", proxy, "create-cratectl-catalog-cached"); w.Code != http.StatusCreated {
		t.Fatal("register OCI proxy", w.Code, w.Body.String())
	}
	list := func(want ...string) {
		t.Helper()
		before := requests.Load()
		w := admin(http.MethodGet, "/v2/_catalog", nil, "")
		var body struct{ Repositories []string }
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || !slices.Equal(body.Repositories, want) {
			t.Fatalf("cached catalog status %d, body %s, expected %v", w.Code, w.Body.String(), want)
		}
		if requests.Load() != before {
			t.Fatal("catalog unexpectedly made an upstream request")
		}
	}
	pull := func() {
		t.Helper()
		w := mavenHTTP(t, s, token, http.MethodGet, "/v2/"+repo+"/"+image+"/manifests/latest", "", "Accept", testOCIImage)
		if w.Code != http.StatusOK || w.Body.String() != root || w.Header().Get("Docker-Content-Digest") != rootDigest {
			t.Fatal("cached graph resolution", w.Code, w.Body.String())
		}
	}
	list()
	pull()
	list(repo + "/" + image)
	member := image + "/blobs/" + childDigest
	if w := admin(http.MethodPut, "/api/v1/repositories/"+repo+"/cache", map[string]string{"path": member}, "expire-catalog-member"); w.Code != http.StatusOK {
		t.Fatal("expire graph dependency", w.Code, w.Body.String())
	}
	list()
	pull()
	list(repo + "/" + image)
	if w := admin(http.MethodPut, "/api/v1/repositories/"+repo+"/decisions", map[string]string{
		"path": member, "digest": strings.TrimPrefix(childDigest, "sha256:"), "decision": "denied",
	}, "deny-cratectl-catalog-child"); w.Code != http.StatusOK {
		t.Fatal("deny graph dependency", w.Code, w.Body.String())
	}
	list()
}

func TestOCIRepositoryCatalogUsesGroupOrderGrantsAndNamespaceOwners(t *testing.T) {
	s, db, token, adminIdentity := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	const hosted = "cratectl-catalog-lower"
	const proxy = "cratectl-catalog-preferred"
	const group = "cratectl-catalog-group"
	const owned = "cratectl-catalog-owned-group"
	const reviewed = "cratectl-catalog-review-group"
	const image = "namespace/workload"
	const manifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`
	digest := crypt.Digest([]byte(manifest))
	path := image + "/manifests/sha256:" + digest
	var upstreamRequests atomic.Int64
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Cache-Control", "max-age=90")
		w.WriteHeader(http.StatusNotFound)
	})}}
	origin.Start()
	defer origin.Close()
	credential, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(t.Context(), db.OwnerDSN, adminIdentity.Tenant, "cratectl-catalog-reader", "reader", credential, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	admin := lifecycleHTTP(t, s, token)
	reader := lifecycleHTTP(t, s, credential)
	for _, configuration := range []store.Repository{
		{Name: hosted, Format: "oci"},
		{Name: proxy, Format: "oci", Mode: "proxy", Access: "restricted", Settings: store.RepositorySettings{
			Upstream: &upstream.Config{URL: origin.URL + "/v2/cratectl-absent-origin/", Networks: []string{"127.0.0.1/32"}},
			Cache:    store.CacheSettings{FreshSeconds: 90, NegativeSeconds: 90},
		}},
		{Name: group, Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{proxy, hosted}}},
		{Name: owned, Format: "oci", Mode: "group", Settings: store.RepositorySettings{
			Members: []string{proxy, hosted}, NamespaceOwners: map[string]string{"namespace/": hosted},
		}},
		{Name: reviewed, Format: "oci", Mode: "group", RequireReview: true, Settings: store.RepositorySettings{Members: []string{hosted}}},
	} {
		if w := admin(http.MethodPost, "/api/v1/repositories", configuration, "create-"+configuration.Name); w.Code != http.StatusCreated {
			t.Fatal("configure group catalog", w.Code, w.Body.String())
		}
	}
	if w := mavenHTTP(t, s, token, http.MethodPut, "/v2/"+hosted+"/"+image+"/manifests/latest", manifest, "Content-Type", testOCIIndex); w.Code != http.StatusCreated {
		t.Fatal("publish lower manifest", w.Code, w.Body.String())
	}
	list := func(want ...string) {
		t.Helper()
		before := upstreamRequests.Load()
		w := reader(http.MethodGet, "/v2/_catalog", nil, "")
		var body struct{ Repositories []string }
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || !slices.Equal(body.Repositories, want) || upstreamRequests.Load() != before {
			t.Fatalf("group catalog status %d, body %s, expected %v", w.Code, w.Body.String(), want)
		}
	}
	grant := func(allow bool, key string) {
		t.Helper()
		if w := admin(http.MethodPut, "/api/v1/repositories/"+proxy+"/grants", map[string]any{
			"actor": "cratectl-catalog-reader", "read": allow, "write": false,
		}, key); w.Code != http.StatusOK {
			t.Fatal("change group member grant", w.Code, w.Body.String())
		}
	}
	list(hosted+"/"+image, owned+"/"+image)
	grant(true, "grant-preferred-catalog")
	list(hosted+"/"+image, owned+"/"+image)
	if w := mavenHTTP(t, s, credential, http.MethodGet, "/v2/"+group+"/"+path, "", "Accept", testOCIIndex); w.Code != http.StatusOK || w.Body.String() != manifest || upstreamRequests.Load() == 0 {
		t.Fatal("group fallback establishes exact proxy absence", w.Code, w.Body.String())
	}
	list(group+"/"+image, hosted+"/"+image, owned+"/"+image)
	if w := admin(http.MethodPut, "/api/v1/repositories/"+hosted+"/decisions", map[string]string{
		"path": path, "digest": digest, "decision": "allowed",
	}, "approve-lower-catalog"); w.Code != http.StatusOK {
		t.Fatal("approve group manifest", w.Code, w.Body.String())
	}
	list(group+"/"+image, hosted+"/"+image, owned+"/"+image, reviewed+"/"+image)
	grant(false, "revoke-preferred-catalog")
	list(hosted+"/"+image, owned+"/"+image, reviewed+"/"+image)
	grant(true, "restore-preferred-catalog")
	if w := admin(http.MethodPut, "/api/v1/repositories/"+proxy+"/cache", map[string]string{"path": path}, "invalidate-preferred-absence"); w.Code != http.StatusOK {
		t.Fatal("expire preferred cache absence", w.Code, w.Body.String())
	}
	list(hosted+"/"+image, owned+"/"+image, reviewed+"/"+image)
}
