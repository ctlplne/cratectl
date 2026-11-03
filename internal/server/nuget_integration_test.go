//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	if (method == "PUT" || method == "DELETE" || method == "POST") && strings.Contains(path, "/api/v2/package") {
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

func TestNuGetListingIsDurableAndPreservesConsumption(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "nuget", Access: "restricted"})
	data, manifest := nugetNupkgFixture(t, "Owned.Package", "1.0+owned")
	body, contentType := nugetMultipart(t, data, 0)
	if w := nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, contentType); w.Code != 201 {
		t.Fatal("publish listing fixture", w.Code)
	}
	path := store.NuGetPath("owned.package", "1.0.0")
	before, e := s.DB.Artifact(ctx, admin, "owned", path)
	if e != nil {
		t.Fatal(e)
	}
	endpoint := "/nuget/owned/api/v2/package/Owned.Package/1.0+owned"
	change := func(method string, expected int) {
		t.Helper()
		w := nugetHTTP(t, s, token, method, endpoint, nil, "")
		if w.Code != expected {
			t.Fatal("native listing transition", method, w.Code, w.Body.String())
		}
	}
	listed := func(expected bool) {
		t.Helper()
		a, e := s.DB.Artifact(ctx, admin, "owned", path)
		if e != nil {
			t.Fatal(e)
		}
		m, e := store.ValidateNuGetArtifact(ctx, a)
		if e != nil || m.IsListed() != expected || !bytes.Equal(m.Nuspec, manifest) || a.Digest != before.Digest || a.Size != before.Size || a.Decision != before.Decision || !a.Created.Equal(before.Created) {
			t.Fatal("listing changed immutable bytes or policy", m.IsListed(), e)
		}
	}
	listed(true) // Existing packages have no explicit listing field.
	change("DELETE", 204)
	change("DELETE", 204) // Native retries are idempotent.
	listed(false)
	for file, expected := range map[string][]byte{"owned.package.1.0.0.nupkg": data, "owned.package.nuspec": manifest} {
		w := nugetHTTP(t, s, token, "GET", "/nuget/owned/flat/owned.package/1.0.0/"+file, nil, "")
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), expected) {
			t.Fatal("unlisting broke pinned consumption", w.Code)
		}
	}
	if versions, e := s.DB.NuGetVersions(ctx, admin, "owned", "owned.package", 10, 4096); e != nil || len(versions) != 1 || versions[0] != "1.0.0" {
		t.Fatal("unlisted version removed from flat index", versions, e)
	}
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	if w := nugetHTTP(t, restarted, token, "POST", endpoint, nil, ""); w.Code != 200 {
		t.Fatal("durable relist after handler restart", w.Code)
	}
	change("POST", 200)
	listed(true)
	// Exhausting the common outbox must roll back the listing and its event.
	var capacity int
	if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT capacity FROM cratectl.queue_policies WHERE queue='events'`).Scan(&capacity); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.DB.SetNuGetListing(ctx, admin, "owned", "Owned.Package", "1.0", false); !errors.Is(e, store.ErrQueueFull) {
		t.Fatal("listing ignored full durable outbox", e)
	}
	listed(true)
	if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=$1 WHERE queue='events'`, capacity)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	request := lifecycleHTTP(t, s, token)
	hold := store.ArtifactStateRequest{Path: path, Digest: before.Digest, Action: "hold", Reason: "Owned listing preservation case"}
	if w := request("PUT", "/api/v1/repositories/owned/artifacts/lifecycle", hold, "listing-hold"); w.Code != 200 {
		t.Fatal("hold listing reference", w.Code)
	}
	change("DELETE", 409)
	listed(true)
	hold.Action, hold.ExpectedRevision = "release_hold", 1
	if w := request("PUT", "/api/v1/repositories/owned/artifacts/lifecycle", hold, "listing-release"); w.Code != 200 {
		t.Fatal("release listing hold", w.Code)
	}
	writer, _ := crypt.Token()
	reader, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "listing-reader", "reader", reader, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if w := nugetHTTP(t, s, reader, "DELETE", endpoint, nil, "", "Authorization", "Bearer "+token); w.Code != 403 {
		t.Fatal("reader API key borrowed bearer write authority", w.Code)
	}
	if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "listing-writer", "writer", writer, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if w := nugetHTTP(t, s, writer, "DELETE", endpoint, nil, ""); w.Code != 403 {
		t.Fatal("ungranted writer changed listing", w.Code)
	}
	grant := func(write bool) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,'owned','listing-writer',true,$2) ON CONFLICT(tenant,repository,actor) DO UPDATE SET can_write=excluded.can_write`, admin.Tenant, write)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	grant(true)
	if w := nugetHTTP(t, s, writer, "DELETE", endpoint, nil, "", "Authorization", "Bearer "+token); w.Code != 204 {
		t.Fatal("API key identity did not control native unlist", w.Code)
	}
	listed(false)
	grant(false)
	if w := nugetHTTP(t, s, writer, "POST", endpoint, nil, "", "Authorization", "Bearer "+token); w.Code != 403 {
		t.Fatal("revoked repository grant borrowed bearer authority", w.Code)
	}
	grant(true)
	if e := store.Revoke(ctx, d.OwnerDSN, writer); e != nil {
		t.Fatal(e)
	}
	if w := nugetHTTP(t, s, writer, "POST", endpoint, nil, "", "Authorization", "Bearer "+token); w.Code != 401 {
		t.Fatal("revoked API key borrowed bearer authority", w.Code)
	}
	// Concurrent relist/unlist serialize under the same tenant fence.
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			method := "POST"
			if n%2 == 0 {
				method = "DELETE"
			}
			codes <- nugetHTTP(t, s, token, method, endpoint, nil, "").Code
		}(n)
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 && code != 204 {
			t.Fatal("concurrent listing mutation failed", code)
		}
	}
	change("POST", 200)
	listed(true)
	hold.Action, hold.ExpectedRevision = "delete", 2
	if w := request("PUT", "/api/v1/repositories/owned/artifacts/lifecycle", hold, "listing-retire"); w.Code != 200 {
		t.Fatal("retire listed package", w.Code)
	}
	change("POST", 404)
	change("DELETE", 404)
	other, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, "nuget-listing-other", "operator", "admin", other, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	otherAdmin, e := s.DB.Authenticate(ctx, other)
	if e != nil {
		t.Fatal(e)
	}
	mavenRepositories(t, s, otherAdmin, store.Repository{Name: "owned", Format: "nuget"})
	if w := nugetHTTP(t, s, other, "POST", endpoint, nil, ""); w.Code != 404 {
		t.Fatal("other tenant relisted an absent coordinate", w.Code)
	}
	if w := nugetHTTP(t, s, other, "PUT", "/nuget/owned/api/v2/package", body, contentType); w.Code != 201 {
		t.Fatal("same coordinate in another tenant inherited retirement", w.Code)
	}
	// Listing must not resurrect retirement or change immutable bytes/policy.
	var events, jobs int
	if e := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*),(SELECT count(*) FROM cratectl.jobs j WHERE j.sequence IN (SELECT sequence FROM cratectl.events WHERE payload::jsonb->>'kind'='nuget.package.listing.changed')) FROM cratectl.events WHERE payload::jsonb->>'kind'='nuget.package.listing.changed'`).Scan(&events, &jobs)
	}); e != nil || events != 14 || jobs < events {
		t.Fatal("listing journal/outbox transaction", events, jobs, e)
	}
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
	data, _ = nugetNupkgFixture(t, "Owned.Package", "10.0")
	body, contentType = nugetMultipart(t, data, 0)
	if w := nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, contentType); w.Code != 201 {
		t.Fatal("tenth version", w.Code, w.Body.String())
	}
	data, _ = nugetNupkgFixture(t, "Owned.Package", "2.0")
	body, contentType = nugetMultipart(t, data, 0)
	if w := nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, contentType); w.Code != 201 {
		t.Fatal("second version", w.Code, w.Body.String())
	}
	index := nugetHTTP(t, s, token, "GET", "/nuget/owned/flat/owned.package/index.json", nil, "")
	var view struct{ Versions []string }
	if index.Code != 200 || json.Unmarshal(index.Body.Bytes(), &view) != nil || strings.Join(view.Versions, ",") != "1.0.0,2.0.0,10.0.0" {
		t.Fatal("version index used text ordering", index.Code, index.Body.String())
	}
	s.NativeVersionLimit = 1
	if w := nugetHTTP(t, s, token, "GET", "/nuget/owned/flat/owned.package/index.json", nil, ""); w.Code != 503 {
		t.Fatal("partial version index returned", w.Code, w.Body.String())
	}
	var count int
	if e := s.DB.Tx(context.Background(), admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='nuget.package.published'`).Scan(&count)
	}); e != nil || count != 3 {
		t.Fatal("failed/conflicting publication created journal effects", count, e)
	}
}
