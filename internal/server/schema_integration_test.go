//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func schemaServer(t *testing.T) (*Server, testdb.Database, string, store.Identity) {
	t.Helper()
	d := testdb.New(t)
	ctx := context.Background()
	if e := store.Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	token, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, "schema-http", "operator", "admin", token, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	db, e := store.Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Pool.Close)
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	b, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	return New(db, b, ""), d, token, i
}

func TestSchemaHTTPMaintenanceRetainsCredentialAndReadiness(t *testing.T) {
	s, d, token, _ := schemaServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	tx, e := owner.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(731445922)`); e != nil {
		t.Fatal(e)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/v1/session", "/api/v1/repositories", "/health/ready"} {
		w := request("GET", path, "")
		if w.Code != 503 || w.Header().Get("Retry-After") != "1" || w.Header().Get("WWW-Authenticate") != "" || !strings.Contains(w.Body.String(), "schema_maintenance") {
			t.Fatal("maintenance response", path, w.Code, w.Body.String())
		}
	}
	if w := request("POST", "/api/v1/repositories", `{"name":"unaccepted","format":"generic"}`); w.Code != 503 {
		t.Fatal("mutation admitted during DDL", w.Code)
	}
	if w := request("GET", "/health/live", ""); w.Code != 200 {
		t.Fatal("liveness unavailable", w.Code)
	}
	if w := request("GET", "/console/", ""); w.Code != 200 {
		t.Fatal("console shell unavailable", w.Code)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if w := request("GET", "/api/v1/session", ""); w.Code != 200 {
		t.Fatal("same credential did not recover", w.Code)
	}
	if w := request("GET", "/api/v1/repositories", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("maintenance mutated repositories", w.Code, w.Body.String())
	}
	if _, e = owner.Exec(ctx, `ALTER TABLE cratectl.artifacts NO FORCE ROW LEVEL SECURITY`); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/api/v1/session", "/health/ready"} {
		w := request("GET", path, "")
		if w.Code != 503 || w.Header().Get("WWW-Authenticate") != "" || !strings.Contains(w.Body.String(), "schema_incompatible") {
			t.Fatal("schema drift response", path, w.Code, w.Body.String())
		}
	}
}

func TestSchemaCurrentNoopDoesNotInterruptSlowUpload(t *testing.T) {
	s, d, token, i := schemaServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repo := store.Repository{Name: "images", Format: "oci"}
	if e := s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { return store.CreateRepository(ctx, tx, i, repo) }); e != nil {
		t.Fatal(e)
	}
	repo, e := s.DB.Repository(ctx, i, repo.Name)
	if e != nil {
		t.Fatal(e)
	}
	id := beginUpload(t, s, ctx, i, repo)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	r := httptest.NewRequest("PATCH", "/v2/images/app/blobs/uploads/"+id, reader).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.ServeHTTP(w, r); close(done) }()
	if _, e = writer.Write([]byte("first")); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 3; n++ {
		if e = store.Migrate(ctx, d.OwnerDSN); e != nil {
			t.Fatal("no-op migration interrupted active upload", e)
		}
	}
	if _, e = writer.Write([]byte("-second")); e != nil {
		t.Fatal(e)
	}
	writer.Close()
	<-done
	if w.Code != 202 {
		t.Fatal("upload after no-op", w.Code, w.Body.String())
	}
	status := httptest.NewRecorder()
	s.oci(status, httptest.NewRequest("GET", "/", nil).WithContext(ctx), i, repo, "app/blobs/uploads/"+id)
	if status.Code != 204 || status.Header().Get("Range") != "0-11" {
		t.Fatal("upload acknowledged wrong bytes", status.Code, status.Header())
	}
}
