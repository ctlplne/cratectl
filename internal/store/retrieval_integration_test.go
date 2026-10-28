//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestRetrievalFencingAndTenantScope(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Pool.Close()
	admin := Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	reader := Identity{Tenant: "test-a", Actor: "reader", Role: "reader"}
	other := Identity{Tenant: "test-b", Actor: "reader", Role: "reader"}
	repo := Repository{Name: fmt.Sprintf("lease-%d", time.Now().UnixNano()), Format: "generic", Mode: "proxy", Access: "tenant", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/r/source/", Networks: []string{"127.0.0.1/32"}}, Cache: CacheSettings{FreshSeconds: 60, StaleSeconds: 60}}}
	if e = s.Tx(ctx, admin, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, admin, repo) }); e != nil {
		t.Fatal(e)
	}
	firstToken, _ := crypt.Token()
	first, e := s.AcquireRetrieval(ctx, reader, repo.Name, "object", firstToken, false)
	if e != nil || !first.Acquired {
		t.Fatal("initial lease failed", e)
	}
	if _, e = s.AcquireRetrieval(ctx, reader, repo.Name, "object", "competing-worker", false); !errors.Is(e, ErrBusy) {
		t.Fatalf("live lease was not coalesced: %v", e)
	}
	if e = s.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until=now()-interval '1 second' WHERE repository=$1`, repo.Name)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	secondToken, _ := crypt.Token()
	second, e := s.AcquireRetrieval(ctx, reader, repo.Name, "object", secondToken, false)
	if e != nil || second.Generation <= first.Generation {
		t.Fatal("expired lease did not advance fence", e)
	}
	objects, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	object, e := objects.Put(ctx, reader.Tenant, bytes.NewBufferString("durable proxy bytes"), "", 19)
	if e != nil {
		t.Fatal(e)
	}
	result := RetrievalResult{Status: 200, Object: &object, FreshSeconds: 60, StaleSeconds: 60, ETag: `"source-v1"`}
	if e = s.CompleteRetrieval(ctx, reader, first, result); !errors.Is(e, ErrLeaseLost) {
		t.Fatalf("stale worker published: %v", e)
	}
	if _, e = s.Artifact(ctx, reader, repo.Name, "object"); !errors.Is(e, ErrNotFound) {
		t.Fatal("stale publication reference exists", e)
	}
	if e = s.CompleteRetrieval(ctx, reader, second, result); e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, reader, second, result); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("completed worker replayed effect", e)
	}
	a, e := s.Artifact(ctx, reader, repo.Name, "object")
	if e != nil || a.Digest != object.Digest {
		t.Fatal("durable reference mismatch", e)
	}
	f, e := objects.OpenVerified(ctx, reader.Tenant, a.Digest, a.Size)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e = s.Retrieval(ctx, other, repo.Name, "object"); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant retrieval leaked", e)
	}
	for _, table := range []string{"repository_grants", "retrievals"} {
		var n int
		if e = s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&n); e != nil || n != 0 {
			t.Fatalf("unscoped %s query exposed data: %v", table, e)
		}
	}
	if e = s.Tx(ctx, admin, true, func(tx pgx.Tx) error { _, e := InvalidateRetrieval(ctx, tx, admin, repo.Name, "object"); return e }); e != nil {
		t.Fatal(e)
	}
	thirdToken, _ := crypt.Token()
	third, e := s.AcquireRetrieval(ctx, reader, repo.Name, "object", thirdToken, false)
	if e != nil {
		t.Fatal(e)
	}
	result.ETag = ""
	if e = s.CompleteRetrieval(ctx, reader, third, result); e != nil {
		t.Fatal(e)
	}
	entry, e := s.Retrieval(ctx, reader, repo.Name, "object")
	if e != nil || entry.ETag != "" {
		t.Fatal("new 200 response retained obsolete validator", e)
	}
}
