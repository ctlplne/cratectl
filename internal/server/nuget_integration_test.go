//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func nugetHTTP(t *testing.T, s *Server, token, method, path string, body []byte, contentType string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if method == "PUT" && strings.Contains(path, "/api/v2/package") {
		r.Header.Set("X-NuGet-ApiKey", token)
	} else {
		r.SetBasicAuth("token", token)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for n := 0; n < len(headers); n += 2 {
		r.Header.Set(headers[n], headers[n+1])
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestNuGetHostedPublicationPolicyBytesAndLifecycle(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	s.PublicURL = "https://localhost:38443"
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "nuget", RequireReview: true})
	data, manifest := nugetNupkgFixture(t, "Owned.Package", "1.0+owned")
	body, contentType := nugetMultipart(t, data, 2)
	push := func(token string, body []byte) *httptest.ResponseRecorder {
		return nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, contentType)
	}
	if w := push(token, body); w.Code != 201 {
		t.Fatal("native package publication", w.Code, w.Body.String())
	}
	if w := push(token, body); w.Code != 409 {
		t.Fatal("duplicate publication", w.Code, w.Body.String())
	}
	index := "/nuget/owned/flat/owned.package/index.json"
	flat := "/nuget/owned/flat/owned.package/1.0.0/"
	packageURL, manifestURL := flat+"owned.package.1.0.0.nupkg", flat+"owned.package.nuspec"
	read := func(method, path string, headers ...string) *httptest.ResponseRecorder {
		return nugetHTTP(t, s, token, method, path, nil, "", headers...)
	}
	if w := read("GET", index); w.Code != 404 {
		t.Fatal("unreviewed version indexed", w.Code)
	}
	for _, p := range []string{packageURL, manifestURL} {
		if w := read("GET", p); w.Code != 403 {
			t.Fatal("unreviewed package or manifest served", w.Code, p)
		}
	}
	path, digest := store.NuGetPath("owned.package", "1.0.0"), crypt.Digest(data)
	decide := func(decision string) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error { _, e := store.Decide(ctx, tx, admin, "owned", path, digest, decision); return e }); e != nil {
			t.Fatal(e)
		}
	}
	decide("allowed")
	w := read("GET", index)
	var versions struct{ Versions []string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &versions) != nil || len(versions.Versions) != 1 || versions.Versions[0] != "1.0.0" {
		t.Fatal("version index", w.Code, w.Body.String())
	}
	for p, expected := range map[string][]byte{packageURL: data, manifestURL: manifest} {
		w := read("GET", p)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), expected) {
			t.Fatal("exact package/manifest bytes", p, w.Code)
		}
		etag := w.Header().Get("ETag")
		if w = read("GET", p, "Range", "bytes=1-7"); w.Code != 206 || !bytes.Equal(w.Body.Bytes(), expected[1:8]) {
			t.Fatal("native range", p, w.Code)
		}
		if w = read("GET", p, "If-None-Match", etag); w.Code != 304 {
			t.Fatal("native conditional read", p, w.Code)
		}
		if w = read("HEAD", p); w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("native HEAD", p, w.Code)
		}
	}
	decide("denied")
	for _, p := range []string{packageURL, manifestURL} {
		if w := read("GET", p); w.Code != 403 {
			t.Fatal("current denial bypassed", p, w.Code)
		}
	}
	if w := read("GET", index); w.Code != 404 {
		t.Fatal("denied package indexed", w.Code)
	}
	decide("allowed")
	request := lifecycleHTTP(t, s, token)
	lifecycle := store.ArtifactStateRequest{Path: path, Digest: digest, Action: "delete", Reason: "Owned NuGet lifecycle regression"}
	if w := request("PUT", "/api/v1/repositories/owned/artifacts/lifecycle", lifecycle, "nuget-delete"); w.Code != 200 {
		t.Fatal("native reference delete", w.Code, w.Body.String())
	}
	for _, p := range []string{index, packageURL, manifestURL} {
		if w := read("GET", p); w.Code != 404 {
			t.Fatal("retired reference remained visible", p, w.Code)
		}
	}
	if w := push(token, body); w.Code != 404 {
		t.Fatal("push resurrected retired reference", w.Code)
	}
	lifecycle.Action, lifecycle.ExpectedRevision = "restore", 1
	if w := request("PUT", "/api/v1/repositories/owned/artifacts/lifecycle", lifecycle, "nuget-restore"); w.Code != 200 {
		t.Fatal("verified native reference restore", w.Code, w.Body.String())
	}
	// Recreating the handler reads durable state, rather than in-memory package maps.
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	if w := nugetHTTP(t, restarted, token, "GET", packageURL, nil, ""); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("reference did not survive handler restart", w.Code)
	}
	reader, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "reader", "reader", reader, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if w := push(reader, body); w.Code != 403 {
		t.Fatal("reader publication admitted", w.Code)
	}
	if e := store.Revoke(ctx, d.OwnerDSN, reader); e != nil {
		t.Fatal(e)
	}
	if w := nugetHTTP(t, s, reader, "GET", index, nil, ""); w.Code != 401 {
		t.Fatal("revoked native credential admitted", w.Code)
	}
	other, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, "nuget-other", "operator", "admin", other, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	otherAdmin, e := s.DB.Authenticate(ctx, other)
	if e != nil {
		t.Fatal(e)
	}
	if w := nugetHTTP(t, s, other, "GET", packageURL, nil, ""); w.Code != 404 {
		t.Fatal("cross-tenant package leaked", w.Code)
	}
	mavenRepositories(t, s, otherAdmin, store.Repository{Name: "owned", Format: "nuget"})
	if w := push(other, body); w.Code != 201 {
		t.Fatal("same coordinate in other tenant", w.Code)
	}
	if w := push("", body); w.Code != 401 {
		t.Fatal("publication without API key admitted", w.Code)
	}
}

func TestNuGetConcurrentCoordinatesAndCompleteIndexBudget(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "nuget"})
	data, _ := nugetNupkgFixture(t, "Owned.Package", "1.0")
	body, contentType := nugetMultipart(t, data, 0)
	var wg sync.WaitGroup
	codes := make(chan int, 4)
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, contentType).Code
		}()
	}
	wg.Wait()
	close(codes)
	created, conflicts := 0, 0
	for code := range codes {
		switch code {
		case 201:
			created++
		case 409:
			conflicts++
		default:
			t.Fatal("concurrent publication", code)
		}
	}
	if created != 1 || conflicts != 3 {
		t.Fatal("native first writer was not unique", created, conflicts)
	}
	data, _ = nugetNupkgFixture(t, "Owned.Package", "2.0")
	body, contentType = nugetMultipart(t, data, 0)
	if w := nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, contentType); w.Code != 201 {
		t.Fatal("second version", w.Code, w.Body.String())
	}
	s.NativeVersionLimit = 1
	if w := nugetHTTP(t, s, token, "GET", "/nuget/owned/flat/owned.package/index.json", nil, ""); w.Code != 503 {
		t.Fatal("partial version index returned", w.Code, w.Body.String())
	}
	var count int
	if e := s.DB.Tx(context.Background(), admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='nuget.package.published'`).Scan(&count)
	}); e != nil || count != 2 {
		t.Fatal("failed/conflicting publication created journal effects", count, e)
	}
}
