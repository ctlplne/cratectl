//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
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
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, body := range map[string]string{
		"owned-release/composer.json": `{"name":"cratectl/composer-app","require":{"cratectl/composer-lib":"^2.4"},"scripts":{"test":"owned-unused"},"autoload":{"psr-4":{"Cratectl\\":"src/"}}}`,
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
