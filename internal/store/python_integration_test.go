//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestPythonSourceFencingPolicyAndRLS(t *testing.T) {
	s, ctx, i, prefix := npmTestStore(t)
	repo := prefix + "-python"
	name := "project"
	filename := "project-1.0-py3-none-any.whl"
	r := Repository{Name: repo, Format: "pypi", Mode: "proxy", RequireReview: true, Settings: RepositorySettings{Upstream: &upstream.Config{URL: "https://index.example/simple/", Networks: []string{"0.0.0.0/0"}}}}
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, r) }); e != nil {
		t.Fatal(e)
	}
	core := "Metadata-Version: 2.4\nName: project\nVersion: 1.0\n\n"
	metadata := PythonFile{Name: name, Version: "1.0", Filename: filename, CoreAvailable: true, Integrity: crypt.Integrity([]byte("file bytes"))}
	encoded, _ := json.Marshal(metadata)
	source := NativeSource{Key: crypt.Digest([]byte(repo)), Format: "pypi", Name: name, Coordinate: filename, Version: "1.0", URL: "https://files.example/" + filename, Integrity: metadata.Integrity, Metadata: encoded}
	catalog := PythonCatalog{Name: name, Files: map[string]string{filename: source.Key}}
	catalogBytes, _ := json.Marshal(catalog)
	objects, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	object, e := objects.Put(ctx, i.Tenant, bytes.NewReader(catalogBytes), "", int64(len(catalogBytes)))
	if e != nil {
		t.Fatal(e)
	}
	result := RetrievalResult{Status: 200, Object: &object, Metadata: catalogBytes, MediaType: PythonCatalogMedia, NativeCatalog: &NativeCatalogPublication{Name: name, Entries: catalog.Files, Sources: []NativeSource{source}}, FreshSeconds: 60}
	first, e := s.AcquireRetrieval(ctx, i, repo, PythonCatalogPath(name), "first-python", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until=now()-interval '1 second' WHERE repository=$1`, repo)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	second, e := s.AcquireRetrieval(ctx, i, repo, PythonCatalogPath(name), "second-python", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, first, result); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale Python catalog writer was not fenced", e)
	}
	if _, e = s.NativeSource(ctx, i, repo, source.Key, "pypi"); !errors.Is(e, ErrNotFound) {
		t.Fatal("stale source descriptor survived", e)
	}
	if e = s.CompleteRetrieval(ctx, i, second, result); e != nil {
		t.Fatal(e)
	}
	view, e := s.PythonView(ctx, i, repo, name, 10, 1<<20)
	if e != nil || len(view) != 1 || len(view[0].Files) != 1 || !view[0].Files[0].Blocked {
		t.Fatal("unreviewed Python source was visible", view, e)
	}
	payload, e := objects.Put(ctx, i.Tenant, bytes.NewBufferString("file bytes"), "", 10)
	if e != nil {
		t.Fatal(e)
	}
	metadata.Validated = true
	metadata.CoreMetadata = core
	metadata.CoreSHA256 = crypt.Digest([]byte(core))
	encoded, _ = json.Marshal(metadata)
	filePath := PythonBlobPath(name, source.Key, filename)
	lease, e := s.AcquireRetrieval(ctx, i, repo, filePath, "file-python", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 200, Object: &payload, Metadata: encoded, FreshSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, repo, filePath); !errors.Is(e, ErrDenied) {
		t.Fatal("quarantined Python bytes were readable", e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := Decide(ctx, tx, i, repo, filePath, payload.Digest, "allowed"); return e }); e != nil {
		t.Fatal(e)
	}
	view, e = s.PythonView(ctx, i, repo, name, 10, 1<<20)
	if e != nil || view[0].Files[0].Blocked || !view[0].Files[0].File.Validated {
		t.Fatal("approved validated Python source stayed hidden", e)
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, e = s.NativeSource(ctx, other, repo, source.Key, "pypi"); !errors.Is(e, ErrNotFound) {
		t.Fatal("native descriptor leaked across tenant scope", e)
	}
	for _, table := range []string{"native_sources", "python_yanks"} {
		var n int
		if e = s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&n); e != nil || n != 0 {
			t.Fatal("unscoped tenant data visible", table, n, e)
		}
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.native_sources SET url='https://evil.example/' WHERE repository=$1`, repo)
		return e
	}); e == nil {
		t.Fatal("runtime could rewrite immutable source bindings")
	}
}

func TestPythonYankReplayAndLegacyEnrichment(t *testing.T) {
	s, ctx, i, prefix := npmTestStore(t)
	repo := prefix + "-python-hosted"
	filename := "project-1.0-py3-none-any.whl"
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, Repository{Name: repo, Format: "pypi"}) }); e != nil {
		t.Fatal(e)
	}
	legacy, _ := json.Marshal(PythonFile{Name: "project", Version: "1.0", Filename: filename})
	a := Artifact{Path: filename, Digest: crypt.Digest([]byte("bytes")), Size: 5, MediaType: "application/octet-stream", Metadata: legacy}
	if e := s.Publish(ctx, i, repo, []Artifact{a}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Artifact(ctx, i, repo, filename); !errors.Is(e, ErrPythonUnvalidated) {
		t.Fatal("legacy unvalidated archive served", e)
	}
	validated := PythonFile{Name: "project", Version: "1.0", Filename: filename, Validated: true}
	a.Metadata, _ = json.Marshal(validated)
	if e := s.PublishPython(ctx, i, repo, a); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Artifact(ctx, i, repo, filename); e != nil {
		t.Fatal(e)
	}
	change := func(yanked bool, key string) Result {
		t.Helper()
		result, e := s.Mutate(ctx, i, repo+key, repo+key, "python.yank.changed", func(tx pgx.Tx) (any, int, error) {
			value, e := SetPythonYank(ctx, tx, i, repo, filename, yanked, "fixture reason")
			return value, 200, e
		})
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	first := change(true, "-yank")
	replay := change(true, "-yank")
	if !replay.Replay || string(first.Body) != string(replay.Body) {
		t.Fatal("yank replay changed its revision")
	}
	view, e := s.PythonView(ctx, i, repo, "project", 10, 1<<20)
	if e != nil || view[0].Files[0].File.Yanked == nil {
		t.Fatal("yank not represented", e)
	}
	change(false, "-unyank")
	view, e = s.PythonView(ctx, i, repo, "project", 10, 1<<20)
	if e != nil || view[0].Files[0].File.Yanked != nil {
		t.Fatal("unyank not represented", e)
	}
}
