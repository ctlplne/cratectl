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

func TestNPMCachedSearchPreservesReviewAndCurrentSourceOrder(t *testing.T) {
	s, ctx, actor, lower := npmTestStore(t)
	proxy, group := lower+"-proxy", lower+"-group"
	config := upstream.Config{URL: "http://127.0.0.1:38443/cratectl-npm-source/", Networks: []string{"127.0.0.1/32"}}
	repositories := []Repository{
		{Name: proxy, Format: "npm", Mode: "proxy", Settings: RepositorySettings{Upstream: &config}},
		{Name: group, Format: "npm", Mode: "group", RequireReview: true,
			Settings: RepositorySettings{Members: []string{proxy, lower}}},
	}
	if err := s.Tx(ctx, actor, true, func(tx pgx.Tx) error {
		for _, repo := range repositories {
			if err := CreateRepository(ctx, tx, actor, repo); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	objects, err := blob.New(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	const name, version = "cratectl-search-copy", "1.0.0"
	put := func(content []byte) blob.Object {
		t.Helper()
		obj, err := objects.Put(ctx, actor.Tenant, bytes.NewReader(content), "", int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		return obj
	}
	decide := func(repo, path, digest string) {
		t.Helper()
		if err := s.Tx(ctx, actor, true, func(tx pgx.Tx) error {
			_, err := Decide(ctx, tx, actor, repo, path, digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	local := put([]byte("Original lower group package"))
	localMetadata := json.RawMessage(`{"name":"cratectl-search-copy","version":"1.0.0","package":{"description":"Hosted lower source","dist":{}}}`)
	localPath := NPMPath(name, version)
	if err := s.PublishNPM(ctx, actor, lower, name, []Artifact{{Path: localPath, Digest: local.Digest, Size: local.Size,
		MediaType: "application/octet-stream", Metadata: localMetadata}}, map[string]string{"latest": version}); err != nil {
		t.Fatal(err)
	}
	decide(lower, localPath, local.Digest)
	search := func(repo, expected string) {
		t.Helper()
		hits, total, err := s.NPMSearch(ctx, actor, repo, name, 0, 20, 100, 16, 1<<20)
		if err != nil || total != len(hits) {
			t.Fatal("search", repo, hits, total, err)
		}
		if expected == "" {
			if total != 0 {
				t.Fatal("unavailable source was advertised", repo, hits)
			}
			return
		}
		if total != 1 || hits[0].Description != expected || hits[0].Version != version || hits[0].Date.IsZero() {
			t.Fatal("wrong search selection", repo, hits)
		}
	}
	search(proxy, "")
	search(group, "")
	original := []byte("Exact preferred proxy artifact bytes")
	content := put(original)
	key := crypt.Digest([]byte("cratectl reviewed npm source identity"))
	source := NPMSource{Key: key, Name: name, Version: version, Tarball: config.URL + "copy.tgz",
		Integrity: crypt.Integrity(original), Package: json.RawMessage(`{"description":"Unvalidated upstream text"}`)}
	catalog := NPMCatalog{Name: name, Versions: map[string]string{version: key}, Tags: map[string]string{"latest": version}}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogObject := put(encoded)
	complete := func(path string, result RetrievalResult) {
		t.Helper()
		lease, err := s.AcquireRetrieval(ctx, actor, proxy, path, "cratectl-npm-search-filler", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteRetrieval(ctx, actor, lease, result); err != nil {
			t.Fatal(err)
		}
	}
	complete(NPMCatalogPath(name), RetrievalResult{Status: 200, Object: &catalogObject, Metadata: encoded, MediaType: NPMCatalogMedia,
		NPMCatalog: &catalog, NPMSources: []NPMSource{source}, FreshSeconds: 60})
	search(proxy, "")
	search(group, "")

	cachePath := NPMBlobPath(name, key)
	metadata, err := json.Marshal(map[string]any{"name": name, "version": version, "source_key": key,
		"integrity": source.Integrity, "package": map[string]string{"description": "Preferred archive-derived description"}})
	if err != nil {
		t.Fatal(err)
	}
	complete(cachePath, RetrievalResult{Status: 200, Object: &content, Metadata: metadata,
		MediaType: "application/octet-stream", FreshSeconds: 60})
	search(proxy, "Preferred archive-derived description")
	search(group, "")
	decide(proxy, cachePath, content.Digest)
	search(group, "Preferred archive-derived description")

	if err := s.Tx(ctx, actor, true, func(tx pgx.Tx) error {
		_, err := InvalidateRetrieval(ctx, tx, actor, proxy, NPMCatalogPath(name))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	search(proxy, "")
	search(group, "")
	complete(NPMCatalogPath(name), RetrievalResult{Status: 404, FreshSeconds: 60})
	search(proxy, "")
	search(group, "Hosted lower source")
}
