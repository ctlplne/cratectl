//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestOCIReadGuardRejectsRetargetedTag(t *testing.T) {
	if os.Getenv("CRATECTL_DSN") == "" {
		t.Fatal("CRATECTL_DSN required; integration never silently skips")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	i := store.Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	repo := fmt.Sprintf("oci-guard-%d", time.Now().UnixNano())
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		return store.CreateRepository(ctx, tx, i, store.Repository{Name: repo, Format: "oci"})
	}); e != nil {
		t.Fatal(e)
	}
	server := New(db, nil, "")
	publish := func(label string) {
		t.Helper()
		data := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"label":"` + label + `"}}`)
		parsed, e := parseOCIManifest(data, "application/vnd.oci.image.index.v1+json")
		if e != nil {
			t.Fatal(e)
		}
		a := store.Artifact{Path: "app/manifests/sha256:" + crypt.Digest(data), Digest: crypt.Digest(data), Size: int64(len(data)), MediaType: parsed.MediaType}
		_, e = db.MutateRepository(ctx, i, repo, "", "", "oci.manifest.published", func(tx pgx.Tx) (any, int, error) {
			return map[string]string{"label": label}, 201, store.PublishOCI(ctx, tx, i, repo, "app", "latest", a, parsed.metadata("app"))
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	publish("before")
	a, e := db.OCIManifest(ctx, i, repo, "app", "latest")
	if e != nil {
		t.Fatal(e)
	}
	source, e := db.Repository(ctx, i, repo)
	if e != nil {
		t.Fatal(e)
	}
	resolved := resolvedArtifact{artifact: a, source: source, ociImage: "app", ociRef: "latest"}
	publish("after")
	if _, e = server.guardResolved(ctx, i, resolved); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("tag retarget admitted old selection: %v", e)
	}
	resolved.ociRef = "sha256:" + a.Digest
	if current, e := server.guardResolved(ctx, i, resolved); e != nil || current.Digest != a.Digest {
		t.Fatalf("immutable digest changed with tag: %+v %v", current, e)
	}
}

func TestSameProxyMissWaitsForSharedFillAdmission(t *testing.T) {
	if os.Getenv("CRATECTL_DSN") == "" {
		t.Fatal("CRATECTL_DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	var fetches atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write([]byte("owned coalesced bytes"))
	}))
	defer origin.Close()
	i := store.Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	repo := store.Repository{Name: fmt.Sprintf("fill-admission-%d", time.Now().UnixNano()), Format: "generic", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60}}}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return store.CreateRepository(ctx, tx, i, repo) }); e != nil {
		t.Fatal(e)
	}
	objects, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	server := New(db, objects, "")
	server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	if e = server.ConfigureConcurrency(16, 2, 32); e != nil {
		t.Fatal(e)
	}
	locked, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- db.Tx(ctx, i, true, func(tx pgx.Tx) error {
			close(locked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	<-locked
	results := make(chan error, 8)
	started := make(chan struct{}, 8)
	for n := 0; n < 8; n++ {
		go func() {
			started <- struct{}{}
			_, e := server.resolveProxy(ctx, i, repo, "same-object", false)
			results <- e
		}()
	}
	for n := 0; n < 8; n++ {
		<-started
	}
	time.Sleep(80 * time.Millisecond)
	close(release)
	if e = <-finished; e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 8; n++ {
		if e = <-results; e != nil {
			t.Errorf("same-key contender was rejected before the owner could acquire its lease: %v", e)
		}
	}
	if fetches.Load() != 1 {
		t.Errorf("same-key origin fetches: %d", fetches.Load())
	}
}
