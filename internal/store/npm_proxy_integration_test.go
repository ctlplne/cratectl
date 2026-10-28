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

func TestNPMSourcePublicationIsFencedAndAtomic(t *testing.T) {
	s, ctx, i, prefix := npmTestStore(t)
	repo := prefix + "-proxy"
	name := "@test/package"
	r := Repository{Name: repo, Format: "npm", Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/npm/source/", Networks: []string{"127.0.0.1/32"}}}}
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, r) }); e != nil {
		t.Fatal(e)
	}
	metadata, _ := json.Marshal(map[string]any{"name": name, "version": "1.0.0", "dist": map[string]string{"integrity": crypt.Integrity([]byte("bytes"))}})
	source := NPMSource{Key: crypt.Digest([]byte(repo)), Name: name, Version: "1.0.0", Tarball: "http://127.0.0.1:38443/npm/source/file.tgz", Integrity: crypt.Integrity([]byte("bytes")), Package: metadata}
	catalog := NPMCatalog{Name: name, Versions: map[string]string{"1.0.0": source.Key}, Tags: map[string]string{"latest": "1.0.0"}}
	encoded, _ := json.Marshal(catalog)
	objects, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	object, e := objects.Put(ctx, i.Tenant, bytes.NewReader(encoded), "", int64(len(encoded)))
	if e != nil {
		t.Fatal(e)
	}
	result := RetrievalResult{Status: 200, Object: &object, Metadata: encoded, MediaType: NPMCatalogMedia, NPMCatalog: &catalog, NPMSources: []NPMSource{source}, FreshSeconds: 60}
	first, e := s.AcquireRetrieval(ctx, i, repo, NPMCatalogPath(name), "first", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until=now()-interval '1 second' WHERE repository=$1`, repo)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	second, e := s.AcquireRetrieval(ctx, i, repo, NPMCatalogPath(name), "second", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, first, result); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale catalog writer published descriptors", e)
	}
	if _, e = s.NPMSource(ctx, i, repo, source.Key); !errors.Is(e, ErrNotFound) {
		t.Fatal("stale descriptor escaped fencing", e)
	}
	bad := result
	badCatalog := catalog
	badCatalog.Versions = map[string]string{"1.0.0": source.Key, "2.0.0": crypt.Digest([]byte("second"))}
	bad.NPMCatalog = &badCatalog
	invalid := source
	invalid.Key = badCatalog.Versions["2.0.0"]
	invalid.Version = "3.0.0"
	bad.NPMSources = []NPMSource{source, invalid}
	if e = s.CompleteRetrieval(ctx, i, second, bad); !errors.Is(e, ErrConflict) {
		t.Fatal("inconsistent catalog bindings accepted", e)
	}
	if _, e = s.NPMSource(ctx, i, repo, source.Key); !errors.Is(e, ErrNotFound) {
		t.Fatal("partial descriptor batch survived rollback", e)
	}
	if e = s.CompleteRetrieval(ctx, i, second, result); e != nil {
		t.Fatal(e)
	}
	view, e := s.NPMView(ctx, i, repo, name, 10, 10, 1<<20)
	if e != nil || len(view) != 1 || len(view[0].Versions) != 1 || view[0].Versions[0].Key != source.Key {
		t.Fatal("atomic catalog view lost source identity", view, e)
	}
	path := NPMBlobPath(name, source.Key)
	lease, e := s.AcquireRetrieval(ctx, i, repo, path, "invalid-source", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 200, Failure: "upstream_package_metadata_mismatch"}); e != nil {
		t.Fatal(e)
	}
	view, e = s.NPMView(ctx, i, repo, name, 10, 10, 1<<20)
	if e != nil || !view[0].Versions[0].Blocked {
		t.Fatal("known invalid source was advertised", view, e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := InvalidateRetrieval(ctx, tx, i, repo, path); return e }); e != nil {
		t.Fatal(e)
	}
	lease, e = s.AcquireRetrieval(ctx, i, repo, path, "missing-source", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 404, FreshSeconds: 5}); e != nil {
		t.Fatal(e)
	}
	view, e = s.NPMView(ctx, i, repo, name, 10, 10, 1<<20)
	if e != nil || !view[0].Versions[0].Blocked {
		t.Fatal("negative-cache source was advertised", e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET fresh_until=now()-interval '1 second' WHERE repository=$1 AND path=$2`, repo, path)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	view, e = s.NPMView(ctx, i, repo, name, 10, 10, 1<<20)
	if e != nil || view[0].Versions[0].Blocked {
		t.Fatal("expired negative cache permanently hid a retryable source", e)
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, e = s.NPMSource(ctx, other, repo, source.Key); !errors.Is(e, ErrNotFound) {
		t.Fatal("descriptor crossed tenant scope", e)
	}
	var n int
	if e = s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.npm_sources`).Scan(&n); e != nil || n != 0 {
		t.Fatal("unscoped source query exposed rows", n, e)
	}
}
