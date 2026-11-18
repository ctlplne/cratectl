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
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
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
	configure(token, store.Repository{Name: "cratectl-catalog-group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{public}}})

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
