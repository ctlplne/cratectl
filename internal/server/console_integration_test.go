//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConsoleSessionUsesCurrentCredentialAndDoesNotExposeSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner := os.Getenv("CRATECTL_OWNER_DSN")
	if owner == "" {
		t.Fatal("owned PostgreSQL owner configuration required")
	}
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	admin, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	worker, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	tenant := "console-" + crypt.Digest([]byte(admin))[:12]
	for role, token := range map[string]string{"admin": admin, "worker": worker} {
		if e = store.Provision(ctx, owner, tenant, "operator", role, token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	s := New(db, nil, "https://localhost:38443")
	delete(s.adapters, "oci")
	invoke := func(path, token string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		s.ServeHTTP(w, r)
		return w
	}
	if w := invoke("/console/", ""); w.Code != 200 {
		t.Fatal("public shell unavailable")
	}
	if w := invoke("/api/v1/session", ""); w.Code != 401 {
		t.Fatal("identity exposed without auth")
	}
	w := invoke("/api/v1/session", admin)
	if w.Code != 200 {
		t.Fatal("current administrator denied", w.Code)
	}
	var body struct {
		Tenant, Actor, Role string
		Formats             []string
		PublicURL           string `json:"public_url"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Tenant != tenant || body.Actor != "operator" || body.Role != "admin" || strings.Join(body.Formats, ",") != "generic,maven,npm,pypi,nuget" || body.PublicURL != "https://localhost:38443" {
		t.Fatal("session identity or supported-adapter scope incorrect")
	}
	if strings.Contains(w.Body.String(), admin) || strings.Contains(w.Body.String(), crypt.Digest([]byte(admin))) || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("session response disclosed a credential or set browser persistence")
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/session", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+admin)
	s.ServeHTTP(w, r)
	if w.Code != 405 || w.Header().Get("Allow") != "GET" {
		t.Fatal("identity route accepted a mutation method")
	}
	if w = invoke("/api/v1/session", worker); w.Code != 401 {
		t.Fatal("worker credential entered public console")
	}
	if e = store.Revoke(ctx, owner, admin); e != nil {
		t.Fatal(e)
	}
	if w = invoke("/api/v1/session", admin); w.Code != 401 {
		t.Fatal("revoked console credential accepted")
	}
}
