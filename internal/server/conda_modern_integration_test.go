//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/conda"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestCondaModernArchivesKeepSeparateRepodataBucketsAndExactBytes(t *testing.T) {
	s, _, token, owner := schemaServer(t)
	s.PublicURL = "https://127.0.0.1:38443"
	ctx := context.Background()
	const first = "cratectl-conda-modern"
	const lower = "cratectl-conda-modern-data"
	const group = "cratectl-conda-modern-group"
	const name = "cratectl-conda-app-1.4.0-fixture_3.conda"
	const app = "linux-64/" + name
	const dependency = "noarch/cratectl-conda-data-1.3.0-fixture_1.conda"
	const legacy = "linux-64/cratectl-conda-dependency-1.0.0-hfixture_0.tar.bz2"
	mavenRepositories(t, s, owner, store.Repository{Name: first, Format: "conda", RequireReview: true},
		store.Repository{Name: lower, Format: "conda", RequireReview: true},
		store.Repository{Name: group, Format: "conda", Mode: "group", RequireReview: true,
			Settings: store.RepositorySettings{Members: []string{first, lower}}})
	fixture := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile("../conda/testdata/cratectl-conda-" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	modernBytes := fixture("modern-app.conda")
	dependencyBytes := fixture("modern-data.conda")
	legacyBytes := fixture("linux-dependency.tar.bz2")
	request := func(repo, method, path string, body []byte, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, s, token, method, "/conda/"+repo+"/"+path, body, "", headers...)
		if w.Code != status {
			t.Fatalf("Conda %s %s/%s returned %d, expected %d: %.250s", method, repo, path, w.Code, status, w.Body.String())
		}
		return w
	}
	decide := func(repo, path string, data []byte, decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, owner, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, owner, repo, path, crypt.Digest(data), decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	request(first, "PUT", "osx-arm64/"+name, modernBytes, 400)
	request(first, "PUT", app, legacyBytes, 400)
	request(first, "PUT", app, modernBytes, 201)
	request(first, "PUT", legacy, legacyBytes, 201)
	request(lower, "PUT", dependency, dependencyBytes, 201)
	request(first, "GET", app, nil, 403)
	decide(first, app, modernBytes, "allowed")
	decide(first, legacy, legacyBytes, "allowed")
	decide(lower, dependency, dependencyBytes, "allowed")
	for _, repo := range []string{first, group} {
		w := request(repo, "GET", "linux-64/repodata.json", nil, 200)
		var catalog struct {
			Legacy map[string]map[string]any `json:"packages"`
			Modern map[string]map[string]any `json:"packages.conda"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &catalog); err != nil || len(catalog.Legacy) != 1 || len(catalog.Modern) != 1 ||
			catalog.Modern[name]["sha256"] != crypt.Digest(modernBytes) {
			t.Fatal("archive formats did not populate separate governed maps", repo, err)
		}
	}
	snapshot := func() string {
		t.Helper()
		w := request(group, "GET", "snapshot.json", nil, 200)
		var ref map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &ref); err != nil || len(ref["sha256"]) != 64 {
			t.Fatal("invalid native group snapshot", err)
		}
		return "snapshots/" + ref["sha256"] + "/"
	}
	pinned := snapshot()
	if w := request(group, "GET", pinned+dependency, nil, 200); !bytes.Equal(w.Body.Bytes(), dependencyBytes) ||
		w.Header().Get("Content-Type") != conda.ModernMedia {
		t.Fatal("modern noarch dependency lost its exact grouped archive or media type")
	}
	if w := request(group, "GET", pinned+app, nil, 206, "Range", "bytes=10-27"); !bytes.Equal(w.Body.Bytes(), modernBytes[10:28]) {
		t.Fatal("modern app download changed original byte range")
	}
	decide(lower, dependency, dependencyBytes, "denied")
	w := request(group, "GET", "noarch/repodata.json", nil, 200)
	if strings.Contains(w.Body.String(), "cratectl-conda-data-") || snapshot() == pinned {
		t.Fatal("modern dependency remained admitted after current denial")
	}
	request(group, "GET", pinned+dependency, nil, 409)
}
