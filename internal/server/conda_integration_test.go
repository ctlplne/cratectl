//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/conda"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestCondaHostedPlatformReviewAndRetainedBytes(t *testing.T) {
	s, database, owner, admin := schemaServer(t)
	ctx := context.Background()
	const repo = "cratectl-conda"
	const route = "/conda/" + repo + "/"
	const noarch = "noarch/cratectl-conda-archive-1.2.0-hfixture_1.tar.bz2"
	const linux = "linux-64/cratectl-conda-dependency-1.0.0-hfixture_0.tar.bz2"
	const linuxFilename = "cratectl-conda-dependency-1.0.0-hfixture_0.tar.bz2"
	const linuxData = "linux-64/repodata.json"
	const lifecyclePath = "/api/v1/repositories/" + repo + "/artifacts/lifecycle"
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "conda", Access: "restricted", RequireReview: true})

	fixture := func(name string) []byte {
		t.Helper()
		body, err := os.ReadFile("../conda/testdata/cratectl-conda-" + name + ".tar.bz2")
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	application, dependency := fixture("valid"), fixture("linux-dependency")
	otherDependency := fixture("linux-dependency-other")
	digest := crypt.Digest(dependency)
	call := func(server *Server, credential, method, target string, content []byte, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, server, credential, method, route+target, content, "", headers...)
		if w.Code != status {
			t.Fatalf("Conda %s %s returned %d, expected %d: %.250s", method, target, w.Code, status, w.Body.String())
		}
		return w
	}
	type record struct {
		conda.Package
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
		MD5    string `json:"md5"`
	}
	index := func(w *httptest.ResponseRecorder, subdir string, count int) map[string]record {
		t.Helper()
		var value struct {
			Info struct {
				Subdir string `json:"subdir"`
			} `json:"info"`
			Packages        map[string]record `json:"packages"`
			CondaPackages   map[string]record `json:"packages.conda"`
			Removed         []string          `json:"removed"`
			RepodataVersion int               `json:"repodata_version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil || value.Info.Subdir != subdir || value.RepodataVersion != 1 ||
			value.Packages == nil || len(value.Packages) != count || value.CondaPackages == nil || value.Removed == nil {
			t.Fatalf("unexpected Conda %s index: %.500s (%v)", subdir, w.Body.String(), err)
		}
		return value.Packages
	}
	call(s, owner, "PUT", noarch, fixture("duplicate"), 400)
	call(s, owner, "PUT", "linux-aarch64/"+linuxFilename, dependency, 400)
	call(s, owner, "PUT", noarch, application, 201)
	if w := call(s, owner, "PUT", linux, dependency, 201); w.Header().Get("X-Checksum-Sha256") != digest {
		t.Fatal("Conda publication did not report the original digest")
	}
	call(s, owner, "PUT", linux, otherDependency, 409)
	call(s, owner, "GET", linux, nil, 403)
	index(call(s, owner, "GET", linuxData, nil, 200), "linux-64", 0)
	index(call(s, owner, "GET", "noarch/repodata.json", nil, 200), "noarch", 0)

	decide := func(path, digest, decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, path, digest, decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide(linux, digest, "allowed")
	decide(noarch, crypt.Digest(application), "allowed")
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-conda-reader"
	if err = store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	call(s, reader, "GET", linuxData, nil, 403)
	api := lifecycleHTTP(t, s, owner)
	if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": true}, "cratectl-conda-grant"); w.Code != 200 {
		t.Fatalf("grant reader: %d %.250s", w.Code, w.Body.String())
	}
	call(s, reader, "PUT", linux, dependency, 403)
	w := call(s, reader, "GET", linuxData, nil, 200)
	etag := w.Header().Get("ETag")
	dependencyRecord := index(w, "linux-64", 1)[linuxFilename]
	md5 := crypt.CompatibilityHash("md5")
	md5.Write(dependency)
	if dependencyRecord.SHA256 != digest || dependencyRecord.MD5 != hex.EncodeToString(md5.Sum(nil)) || dependencyRecord.Size != int64(len(dependency)) {
		t.Fatalf("platform index lost original byte binding: %+v", dependencyRecord)
	}
	w = call(s, reader, "GET", "noarch/current_repodata.json", nil, 200)
	for _, entry := range index(w, "noarch", 1) {
		if !slices.Equal(entry.Depends, []string{"cratectl-conda-dependency >=1.0"}) || entry.SHA256 != crypt.Digest(application) {
			t.Fatalf("noarch index lost the dependency or its original digest: %+v", entry)
		}
	}
	index(call(s, reader, "GET", "linux-aarch64/repodata.json", nil, 200), "linux-aarch64", 0)
	call(s, reader, "GET", linuxData, nil, 304, "If-None-Match", etag)
	if out, err := s.DB.CondaRepodata(ctx, admin, repo, "linux-64", 1, 125); out != "" || !errors.Is(err, store.ErrMetadataLimit) {
		t.Fatalf("oversize metadata did not fail closed: %.200s %v", out, err)
	}
	w = call(s, reader, "GET", linux, nil, 206, "Range", "bytes=1-7")
	if !bytes.Equal(w.Body.Bytes(), dependency[1:8]) {
		t.Fatal("Conda range changed the selected archive bytes")
	}
	decide(linux, digest, "denied")
	index(call(s, reader, "GET", linuxData, nil, 200, "If-None-Match", etag), "linux-64", 0)
	call(s, reader, "GET", linux, nil, 403)
	decide(linux, digest, "allowed")

	state, err := s.DB.ArtifactState(ctx, admin, repo, linux)
	if err != nil {
		t.Fatal(err)
	}
	mutation := store.ArtifactStateRequest{Path: linux, Digest: digest, Action: "delete", ExpectedRevision: state.Revision,
		Reason: "Retire the owned Conda fixture"}
	if w := api("PUT", lifecyclePath, mutation, "cratectl-conda-delete"); w.Code != 200 {
		t.Fatalf("delete Conda archive: %d %.250s", w.Code, w.Body.String())
	}
	index(call(s, reader, "GET", linuxData, nil, 200), "linux-64", 0)
	call(s, reader, "GET", linux, nil, 404)
	state, err = s.DB.ArtifactState(ctx, admin, repo, linux)
	if err != nil || !state.Deleted {
		t.Fatalf("inspect deleted Conda archive: %+v %v", state, err)
	}
	mutation.Action, mutation.ExpectedRevision = "restore", state.Revision
	mutation.Reason = "Restore the verified Conda fixture"
	if w := api("PUT", lifecyclePath, mutation, "cratectl-conda-restore"); w.Code != 200 {
		t.Fatalf("restore Conda archive: %d %.250s", w.Code, w.Body.String())
	}
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	index(call(restarted, reader, "GET", linuxData, nil, 200), "linux-64", 1)
	if w := call(restarted, reader, "GET", linux, nil, 200); !bytes.Equal(w.Body.Bytes(), dependency) {
		t.Fatal("restored Conda archive changed after restart")
	}

	otherToken, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, database.OwnerDSN, "cratectl-conda-other", "cratectl-conda-admin", "admin", otherToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other, err := s.DB.Authenticate(ctx, otherToken)
	if err != nil {
		t.Fatal(err)
	}
	call(s, otherToken, "GET", linuxData, nil, 404)
	mavenRepositories(t, s, other, store.Repository{Name: repo, Format: "conda"})
	call(s, otherToken, "PUT", linux, otherDependency, 201)
	if got := index(call(s, otherToken, "GET", linuxData, nil, 200), "linux-64", 1)[linuxFilename].SHA256; got != crypt.Digest(otherDependency) {
		t.Fatal("second tenant did not see its own index binding")
	}
	if w := call(s, otherToken, "GET", linux, nil, 200); !bytes.Equal(w.Body.Bytes(), otherDependency) {
		t.Fatal("second tenant did not get its own bytes")
	}
}
