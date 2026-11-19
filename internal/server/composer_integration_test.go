//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func composerFixture(t *testing.T, data string) []byte {
	t.Helper()
	const manifest = `{"name":"cratectl/composer-app","require":{"cratectl/composer-lib":"^2.4"},"scripts":{"test":"owned-unused"},"autoload":{"psr-4":{"Cratectl\\":"src/"}}}`
	return composerZipFixture(t, manifest, data)
}

func composerZipFixture(t *testing.T, manifest, data string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, body := range map[string]string{
		"owned-release/composer.json": manifest,
		"owned-release/src/owned.php": data,
	} {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestComposerGroupSelectsOneOwnerAndFencesOldDownloadURLs(t *testing.T) {
	s, database, adminToken, admin := schemaServer(t)
	s.PublicURL = "https://127.0.0.1:38443"
	ctx := context.Background()
	const preferred = "cratectl-composer-first"
	const lower = "cratectl-composer-second"
	const group = "cratectl-composer-group"
	const explicit = "cratectl-composer-owner"
	const file = "dist/cratectl/composer-app/1.2.3.zip"
	const index = "p2/cratectl/composer-app.json"
	members := []string{preferred, lower}
	mavenRepositories(t, s, admin,
		store.Repository{Name: preferred, Format: "composer", Access: "restricted", RequireReview: true},
		store.Repository{Name: lower, Format: "composer", Access: "restricted"},
		store.Repository{Name: group, Format: "composer", Mode: "group", Access: "restricted", Settings: store.RepositorySettings{Members: members}},
		store.Repository{Name: explicit, Format: "composer", Mode: "group", Access: "restricted", Settings: store.RepositorySettings{
			Members: members, NamespaceOwners: map[string]string{"cratectl/composer-app/": lower},
		}},
	)
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-composer-group-reader"
	if err := store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := s.DB.Authenticate(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	api := lifecycleHTTP(t, s, adminToken)
	grant := func(repo string, enabled bool) {
		t.Helper()
		key := "cratectl-composer-grant-" + repo
		if !enabled {
			key += "-revoke"
		}
		if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": enabled}, key); w.Code != 200 {
			t.Fatal("change Composer grants", w.Code, w.Body.String())
		}
	}
	request := func(repo, token, method, path string, raw []byte, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, s, token, method, "/composer/"+repo+"/"+path, raw, "")
		if w.Code != want {
			t.Fatalf("Composer %s %s %s returned %d, expected %d: %.300s", repo, method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	metadata := func(repo string, versions ...string) {
		t.Helper()
		w := request(repo, reader, "GET", index, nil, 200)
		var projected struct{ Packages map[string][]composerVersion }
		if err := json.Unmarshal(w.Body.Bytes(), &projected); err != nil {
			t.Fatal(err)
		}
		rows := projected.Packages["cratectl/composer-app"]
		if len(rows) != len(versions) {
			t.Fatalf("Composer group advertised an unexpected version set: %v", rows)
		}
		for n, row := range rows {
			if row.Version != versions[n] || !strings.HasPrefix(row.Dist.URL, s.PublicURL+"/composer/"+repo+"/dist/") ||
				!strings.HasSuffix(row.Dist.URL, "?sha256="+row.Dist.Reference) {
				t.Fatal("Composer group did not bind its owned version to an exact download address", row)
			}
		}
	}
	original := composerFixture(t, "Owned lower Composer archive.")
	higher := composerFixture(t, "Owned preferred Composer archive.")
	old := crypt.Digest(original)
	newer := crypt.Digest(higher)
	oldURL, newURL := file+"?sha256="+old, file+"?sha256="+newer
	grant(group, true)
	grant(explicit, true)
	grant(lower, true)
	request(lower, adminToken, "PUT", file, original, 201)
	request(lower, adminToken, "PUT", "dist/cratectl/composer-app/2.0.0.zip", original, 201)
	request(group, reader, "GET", index, nil, 403)
	metadata(explicit, "1.2.3", "2.0.0")
	grant(preferred, true)
	metadata(group, "1.2.3", "2.0.0")
	request(group, reader, "GET", file, nil, 400)
	got := request(group, reader, "GET", oldURL, nil, 200)
	if got.Header().Get("X-Cratectl-Repository") != lower || !bytes.Equal(got.Body.Bytes(), original) {
		t.Fatal("first package absence did not select the exact lower member")
	}
	groupRepo, err := s.DB.Repository(ctx, identity, group)
	if err != nil {
		t.Fatal(err)
	}
	entry, source, err := s.DB.ComposerGroupArtifact(ctx, identity, group, file, old, groupRepo.SourceRevision)
	if err != nil {
		t.Fatal(err)
	}
	selected := resolvedArtifact{artifact: entry, source: source, groups: []string{group}, groupRevisions: map[string]int64{group: groupRepo.SourceRevision}}
	request(preferred, adminToken, "PUT", file, higher, 201)
	request(group, adminToken, "PUT", file, higher, 405)
	request(group, reader, "GET", index, nil, 404)
	request(group, reader, "GET", oldURL, nil, 403)
	if _, err := s.guardResolved(ctx, identity, selected); !errors.Is(err, store.ErrDenied) {
		t.Fatalf("previous Composer selection bypassed newly owning member: %v", err)
	}
	decide := func(decision string) {
		t.Helper()
		err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, preferred, file, newer, decision)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	decide("allowed")
	metadata(group, "1.2.3")
	request(group, reader, "GET", oldURL, nil, 409)
	got = request(group, reader, "GET", newURL, nil, 200)
	if got.Header().Get("X-Cratectl-Repository") != preferred || !bytes.Equal(got.Body.Bytes(), higher) {
		t.Fatal("Composer group did not select the preferred member's exact bytes")
	}
	request(group, reader, "GET", "dist/cratectl/composer-app/2.0.0.zip?sha256="+old, nil, 404)
	decide("denied")
	request(group, reader, "GET", index, nil, 404)
	request(group, reader, "GET", newURL, nil, 403)
	request(explicit, reader, "GET", oldURL, nil, 200)
	grant(preferred, false)
	request(group, reader, "GET", index, nil, 403)
	request(explicit, reader, "GET", oldURL, nil, 200)
}

func TestComposerHostedBindsArchiveAndCurrentTenantPolicy(t *testing.T) {
	s, database, adminToken, admin := schemaServer(t)
	const repo = "cratectl-composer"
	const repository = "/composer/" + repo + "/"
	const artifact = "dist/cratectl/composer-app/1.2.3.zip"
	const index = "p2/cratectl/composer-app.json"
	s.PublicURL = "https://127.0.0.1:38443"
	api := lifecycleHTTP(t, s, adminToken)
	if w := api("POST", "/api/v1/repositories", map[string]any{"name": repo, "format": "composer", "access": "restricted", "require_review": true}, "cratectl-composer-repo"); w.Code != 201 {
		t.Fatal("create Composer repository", w.Code, w.Body.String())
	}
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Provision(ctx, database.OwnerDSN, admin.Tenant, "cratectl-composer-reader", "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := func(server *Server, token, method, path string, raw []byte, want int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, server, token, method, repository+path, raw, "", headers...)
		if w.Code != want {
			t.Fatalf("Composer %s %s returned %d, expected %d: %.350s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	request(s, reader, "GET", "packages.json", nil, 403)
	const management = "/api/v1/repositories/" + repo
	if w := api("PUT", management+"/grants", map[string]any{"actor": "cratectl-composer-reader", "read": true}, "cratectl-composer-grant"); w.Code != 200 {
		t.Fatal("grant Composer reader", w.Code, w.Body.String())
	}
	root := request(s, reader, "GET", "packages.json", nil, 200)
	if !strings.Contains(root.Body.String(), `"metadata-url":"`+repository+`p2/%package%.json"`) {
		t.Fatal("wrong stock Composer metadata root")
	}
	original := composerFixture(t, "Owned inert bytes in first Composer tenant.")
	replacement := composerFixture(t, "Owned inert bytes in second Composer tenant.")
	digest := crypt.Digest(original)
	request(s, reader, "PUT", artifact, original, 403)
	request(s, adminToken, "PUT", artifact, original, 201)
	request(s, adminToken, "PUT", artifact, original, 201)
	request(s, adminToken, "PUT", artifact, replacement, 409)
	request(s, adminToken, "PUT", "dist/cratectl/other/1.2.3.zip", original, 400)
	request(s, reader, "GET", index, nil, 404)
	request(s, reader, "GET", artifact, nil, 403)
	decide := func(decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, artifact, digest, decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide("allowed")
	manifest := request(s, reader, "GET", index, nil, 200)
	var read struct {
		Packages map[string][]composerVersion
	}
	if err := json.Unmarshal(manifest.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	rows := read.Packages["cratectl/composer-app"]
	if len(rows) != 1 || rows[0].Version != "1.2.3" || rows[0].Normalized != "1.2.3.0" ||
		rows[0].Require["cratectl/composer-lib"] != "^2.4" || rows[0].Dist.URL != s.PublicURL+repository+artifact ||
		rows[0].Dist.SHA1 != crypt.SHA1(original) || rows[0].Dist.Reference != digest || strings.Contains(manifest.Body.String(), "owned-unused") {
		t.Fatal("incorrect package discovery projection", manifest.Body.String())
	}
	tag := manifest.Header().Get("ETag")
	request(s, reader, "GET", index, nil, 304, "If-None-Match", tag)
	w := request(s, reader, "GET", artifact, nil, 206, "Range", "bytes=1-7")
	if !bytes.Equal(w.Body.Bytes(), original[1:8]) {
		t.Fatal("Composer range did not preserve exact bytes")
	}
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	if w := request(restarted, reader, "GET", artifact, nil, 200); !bytes.Equal(w.Body.Bytes(), original) {
		t.Fatal("Composer archive changed after restart")
	}
	decide("denied")
	request(restarted, reader, "GET", index, nil, 404, "If-None-Match", tag)
	request(restarted, reader, "GET", artifact, nil, 403)

	other, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(ctx, database.OwnerDSN, "cratectl-composer-other", "cratectl-composer-operator", "admin", other, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request(s, other, "GET", index, nil, 404)
	api = lifecycleHTTP(t, s, other)
	if w := api("POST", "/api/v1/repositories", map[string]any{"name": repo, "format": "composer"}, "cratectl-composer-other"); w.Code != 201 {
		t.Fatal("create Composer repository in other tenant", w.Code, w.Body.String())
	}
	request(s, other, "PUT", artifact, replacement, 201)
	if w := request(s, other, "GET", artifact, nil, 200); !bytes.Equal(w.Body.Bytes(), replacement) {
		t.Fatal("Composer crossed tenant package identities")
	}
}

func TestComposerHostedSeparatesDevelopmentMetadataFromTaggedVersions(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	const repo = "cratectl-composer-development"
	const root = "/composer/" + repo + "/"
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "composer"})
	type testVersion struct{ version, normalized string }
	versions := []testVersion{
		{"1.2.3", "1.2.3.0"}, {"1.2.4-alpha1", "1.2.4.0-alpha1"},
		{"1.2.4-rc2", "1.2.4.0-RC2"}, {"dev-fixture", "dev-fixture"},
	}
	var development []byte
	for _, v := range versions {
		data := composerFixture(t, "Owned Composer version "+v.version)
		if v.version == "dev-fixture" {
			development = data
		}
		w := nugetHTTP(t, s, token, "PUT", root+"dist/cratectl/composer-app/"+v.version+".zip", data, "")
		if w.Code != 201 {
			t.Fatalf("publish Composer %s: %d %.250s", v.version, w.Code, w.Body.String())
		}
	}
	check := func(index string, want ...testVersion) {
		t.Helper()
		w := nugetHTTP(t, s, token, "GET", root+index, nil, "")
		var result struct{ Packages map[string][]composerVersion }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("read Composer index: %d %.250s", w.Code, w.Body.String())
		}
		rows := result.Packages["cratectl/composer-app"]
		if len(rows) != len(want) {
			t.Fatal("Composer indices contained unrequested version stabilities")
		}
		for n, row := range rows {
			if row.Version != want[n].version || row.Normalized != want[n].normalized {
				t.Fatal("Composer normalized or grouped the version incorrectly", row)
			}
		}
	}
	check("p2/cratectl/composer-app.json", versions[:3]...)
	check("p2/cratectl/composer-app~dev.json", versions[3])
	ctx := context.Background()
	err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, err := store.Decide(ctx, tx, admin, repo, "dist/cratectl/composer-app/dev-fixture.zip", crypt.Digest(development), "denied")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := nugetHTTP(t, s, token, "GET", root+"p2/cratectl/composer-app~dev.json", nil, ""); w.Code != 404 {
		t.Fatal("denied development version remained visible", w.Code)
	}
	check("p2/cratectl/composer-app.json", versions[:3]...)
}
