//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestComposerHostedSearchAndListFollowCurrentPolicy(t *testing.T) {
	s, database, adminToken, admin := schemaServer(t)
	const repo = "cratectl-composer-search"
	const base = "/composer/" + repo + "/"
	const index = "search.json?q=release+utility&type=library"
	const name = "cratectl/release_tools"
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "composer", Access: "restricted", RequireReview: true})
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = store.Provision(ctx, database.OwnerDSN, admin.Tenant, "cratectl-composer-search-reader", "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	read := func(token, path string, status int) []byte {
		t.Helper()
		reply := nugetHTTP(t, s, token, "GET", base+path, nil, "")
		if reply.Code != status {
			t.Fatalf("Composer search %s returned %d, expected %d: %.300s", path, reply.Code, status, reply.Body.String())
		}
		return reply.Body.Bytes()
	}
	read(reader, index, 403)
	allowed := func(path, digest, decision string) {
		t.Helper()
		err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, path, digest, decision)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	api := lifecycleHTTP(t, s, adminToken)
	if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{
		"actor": "cratectl-composer-search-reader", "read": true,
	}, "cratectl-composer-search-grant"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	type installed struct{ path, digest string }
	publish := func(pkg, version, description string) installed {
		t.Helper()
		path := "dist/" + pkg + "/" + version + ".zip"
		manifest := fmt.Sprintf(`{"name":%q,"description":%q}`, pkg, description)
		body := composerZipFixture(t, manifest, "Owned Composer search bytes for "+pkg+" "+version)
		if w := nugetHTTP(t, s, adminToken, "PUT", base+path, body, ""); w.Code != 201 {
			t.Fatal("upload Composer discovery fixture", w.Code, w.Body.String())
		}
		return installed{path: path, digest: crypt.Digest(body)}
	}
	first := publish(name, "1.0.0", "Release automation utility")
	second := publish(name, "2.0.0", "New release automation utility")
	other := publish("cratectl/release-tools", "1.0.0", "Release planning utility")
	allowed(first.path, first.digest, "allowed")
	allowed(other.path, other.digest, "allowed")
	read(reader, "search.json?q=release&q=utility", 400)
	read(reader, "list.json?filter=cratectl/*&unknown=1", 400)
	meta := string(read(reader, "packages.json", 200))
	if !strings.Contains(meta, "search.json?q=%query%") || !strings.Contains(meta, "list.json") {
		t.Fatal("Composer root did not advertise stock discovery")
	}
	var results struct {
		Results []composerSearchResult
		Total   int
	}
	if err := json.Unmarshal(read(reader, index, 200), &results); err != nil || results.Total != 2 || len(results.Results) != 2 ||
		results.Results[1].Name != name || results.Results[1].Description != "Release automation utility" {
		t.Fatal("Composer search did not use current review and distinct coordinates", results, err)
	}
	if list := string(read(reader, "list.json?filter=cratectl%2Frelease_*", 200)); list != `{"packageNames":["cratectl/release_tools"]}` {
		t.Fatal("Composer wildcard filtering treated the literal underscore as a wildcard", list)
	}
	allowed(second.path, second.digest, "allowed")
	if err := json.Unmarshal(read(reader, index, 200), &results); err != nil || results.Total != 2 ||
		results.Results[1].Description != "New release automation utility" {
		t.Fatal("Composer search did not select the newest visible matching description", results, err)
	}
	allowed(first.path, first.digest, "denied")
	allowed(second.path, second.digest, "denied")
	if text := string(read(reader, index, 200)); strings.Contains(text, name) || !strings.Contains(text, "cratectl/release-tools") {
		t.Fatal("denied Composer packages remained discoverable", text)
	}
	if got := string(read(reader, "search.json?q=release&type=composer-plugin", 200)); got != `{"results":[],"total":0}` {
		t.Fatal("unsupported Composer package type was advertised", got)
	}
}
