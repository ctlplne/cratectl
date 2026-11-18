//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestNPMHostedSearchUsesCurrentVersionsPolicyGrantsAndTenants(t *testing.T) {
	s, db, token, admin := schemaServer(t)
	ctx := t.Context()
	const repo = "cratectl-npm-search"
	configuration := store.Repository{Name: repo, Format: "npm", Access: "restricted", RequireReview: true}
	mavenRepositories(t, s, admin, configuration)
	provision := func(tenant, actor, role string) (string, store.Identity) {
		t.Helper()
		token, err := crypt.Token()
		if err == nil {
			err = store.Provision(ctx, db.OwnerDSN, tenant, actor, role, token, time.Now().Add(time.Hour))
		}
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.DB.Authenticate(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		return token, id
	}
	reader, _ := provision(admin.Tenant, "cratectl-reader", "reader")
	otherToken, other := provision("cratectl-other-search", "cratectl-operator", "admin")
	mavenRepositories(t, s, other, configuration)

	publish := func(who store.Identity, name, version, description string) store.Artifact {
		t.Helper()
		obj, err := s.Blobs.Put(ctx, who.Tenant, strings.NewReader(description), "", int64(len(description)))
		if err != nil {
			t.Fatal(err)
		}
		meta, err := json.Marshal(map[string]any{"name": name, "version": version, "package": map[string]any{
			"name": name, "version": version, "description": description, "dist": map[string]string{"integrity": obj.Digest},
		}})
		if err != nil {
			t.Fatal(err)
		}
		artifact := store.Artifact{Path: store.NPMPath(name, version), Digest: obj.Digest, Size: obj.Size,
			MediaType: "application/octet-stream", Metadata: meta}
		if err := s.DB.PublishNPM(ctx, who, repo, name, []store.Artifact{artifact}, map[string]string{"latest": version}); err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	decision := func(actor string, a store.Artifact, value string) {
		t.Helper()
		data, err := json.Marshal(map[string]string{"path": a.Path, "digest": a.Digest, "decision": value})
		if err != nil {
			t.Fatal(err)
		}
		w := mavenHTTP(t, s, actor, http.MethodPut, "/api/v1/repositories/"+repo+"/decisions", string(data),
			"Idempotency-Key", "cratectl-npm-"+value+"-"+a.Digest[:10])
		if w.Code != http.StatusOK {
			t.Fatal("decision", w.Code, w.Body.String())
		}
	}
	const name = "cratectl-lib"
	first := publish(admin, name, "2.0.0", "First tenant tagged release")
	newer := publish(admin, name, "10.0.0", "First tenant newer release")
	scoped := publish(admin, "@cratectl/lib", "1.0.0", "First tenant scoped release")
	outside := publish(other, name, "2.0.0", "Second tenant release")
	decision(otherToken, outside, "allowed")

	endpoint := "/npm/" + repo + "/-/v1/search"
	read := func(actor, query string, total int, want ...string) {
		t.Helper()
		w := mavenHTTP(t, s, actor, http.MethodGet, endpoint+"?"+query, "")
		var body struct {
			Total   int               `json:"total"`
			Objects []npmSearchObject `json:"objects"`
		}
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "private, no-store" ||
			json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Total != total || body.Objects == nil || len(body.Objects) != len(want) {
			t.Fatal("search", query, w.Code, w.Body.String())
		}
		for n, hit := range body.Objects {
			pkg := hit.Package
			got := pkg.Name + " " + pkg.Version + " " + pkg.Description
			if got != want[n] || pkg.Maintainers == nil || pkg.Date.IsZero() {
				t.Fatalf("search hit %d = %q, want %q", n, got, want[n])
			}
		}
	}
	read(token, "text=cratectl", 0)
	read(otherToken, "text=cratectl", 1, "cratectl-lib 2.0.0 Second tenant release")
	decision(token, first, "allowed")
	decision(token, scoped, "allowed")
	read(token, "text=cratectl", 2, "cratectl-lib 2.0.0 First tenant tagged release", "@cratectl/lib 1.0.0 First tenant scoped release")
	read(token, "text=cratectl&from=1&size=1", 2, "@cratectl/lib 1.0.0 First tenant scoped release")
	read(token, "text=%25", 0)
	decision(token, newer, "allowed")
	read(token, "text=CRATECTL-lib", 1, "cratectl-lib 10.0.0 First tenant newer release")
	if err := s.DB.ChangeNPMTag(ctx, admin, repo, name, "latest", "2.0.0", false); err != nil {
		t.Fatal(err)
	}
	read(token, "text=cratectl-lib", 1, "cratectl-lib 2.0.0 First tenant tagged release")
	decision(token, first, "denied")
	read(token, "text=cratectl-lib", 1, "cratectl-lib 10.0.0 First tenant newer release")

	status := func(actor, method, query string, want int) {
		t.Helper()
		w := mavenHTTP(t, s, actor, method, endpoint+"?"+query, "")
		if w.Code != want || method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("search authorization or method", method, query, w.Code, w.Body.String())
		}
	}
	status(token, http.MethodHead, "text=cratectl", http.StatusOK)
	status(token, http.MethodPost, "text=cratectl", http.StatusMethodNotAllowed)
	status(reader, http.MethodGet, "text=cratectl", http.StatusForbidden)
	grant := func(allow bool, key string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"actor": "cratectl-reader", "read": allow, "write": false})
		w := mavenHTTP(t, s, token, http.MethodPut, "/api/v1/repositories/"+repo+"/grants", string(body),
			"Idempotency-Key", key)
		if w.Code != http.StatusOK {
			t.Fatal("grant", w.Code, w.Body.String())
		}
	}
	grant(true, "cratectl-search-allow")
	read(reader, "text=cratectl-lib", 1, "cratectl-lib 10.0.0 First tenant newer release")
	s.NativeVersionLimit = 1
	status(reader, http.MethodGet, "text=cratectl", http.StatusServiceUnavailable)
	grant(false, "cratectl-search-deny")
	status(reader, http.MethodGet, "text=cratectl", http.StatusForbidden)
}
