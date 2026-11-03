//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestOCIMultipleAcceptFieldsServeExactBytesAndPreservePolicy(t *testing.T) {
	s, _, token, _ := schemaServer(t) // Actual migrated PostgreSQL and filesystem CAS.
	admin := lifecycleHTTP(t, s, token)
	if w := admin("POST", "/api/v1/repositories", store.Repository{Name: "accept-fields", Format: "oci"}, "create-accept-fields"); w.Code != 201 {
		t.Fatal("create", w.Code, w.Body.String())
	}
	body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`
	path := "/v2/accept-fields/app/manifests/latest"
	publish := httptest.NewRequest("PUT", path, strings.NewReader(body))
	publish.Header.Set("Authorization", "Bearer "+token)
	publish.Header.Set("Content-Type", testOCIIndex)
	publish.Header.Set("Idempotency-Key", "publish-accept-fields")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, publish)
	if w.Code != 201 {
		t.Fatal("publish", w.Code, w.Body.String())
	}
	digest := crypt.Digest([]byte(body))
	request := func(method string, fields []string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		for _, field := range fields {
			r.Header.Add("Accept", field)
		}
		response := httptest.NewRecorder()
		s.ServeHTTP(response, r)
		return response
	}
	fields := []string{"application/vnd.docker.distribution.manifest.list.v2+json", testOCIIndex}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := request(method, fields)
		if w.Code != 200 || w.Header().Get("Content-Type") != testOCIIndex || w.Header().Get("Docker-Content-Digest") != "sha256:"+digest {
			t.Fatal("accepted representation lost its bytes or identity", method, w.Code, w.Header())
		}
		if method == http.MethodGet && w.Body.String() != body || method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("incorrect body semantics", method)
		}
		if w := request(method, []string{"*/*", testOCIIndex + ";q=0"}); w.Code != 406 {
			t.Fatal("later specific exclusion was bypassed", method, w.Code)
		}
	}
	if w := admin("PUT", "/api/v1/repositories/accept-fields/decisions", map[string]string{"path": "app/manifests/sha256:" + digest, "digest": digest, "decision": "denied"}, "deny-accept-fields"); w.Code != 200 {
		t.Fatal("deny", w.Code, w.Body.String())
	}
	if w := request(http.MethodGet, fields); w.Code != 403 {
		t.Fatal("combined Accept fields bypassed exact digest policy", w.Code)
	}
}
