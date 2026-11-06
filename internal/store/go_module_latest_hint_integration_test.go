//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestGoModuleLatestAdvertisementUsesCommonTransactionAndCurrentFences(t *testing.T) {
	for _, scenario := range []string{"complete", "source", "lease", "queue", "tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			mod := "go.cratectl.invalid/Owned/intake"
			data := []byte("{\n \"Version\":\"v1.0.0\", \"Origin\":{\"opaque\":true}\n}\n")
			latest, e := NewGoModuleLatest(mod, data)
			if e != nil {
				t.Fatal(e)
			}
			object, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(data), "", int64(len(data)))
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(latest)
			result := RetrievalResult{Status: 200, Object: &object, MediaType: GoModuleLatestMedia, Metadata: raw, FreshSeconds: 60, GoLatest: &latest}
			lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleLatestPath(mod), "owned-latest-advertisement", false)
			if e != nil || !lease.Acquired {
				t.Fatal(e)
			}
			identity := f.i
			want := error(nil)
			query := ""
			switch scenario {
			case "source":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
				want = ErrSourceChanged
			case "lease":
				query = `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='owned'`
				want = ErrLeaseLost
			case "tenant":
				identity = Identity{Tenant: "other-owned-tenant", Actor: "operator", Role: "admin"}
				want = ErrNotFound
			case "queue":
				if _, e = f.s.SetQueuePolicy(ctx, f.i, "owned-latest-small-queue", "owned-latest-small-queue", QueuePolicy{Queue: "integrity", Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); e != nil {
					t.Fatal(e)
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					if e := enqueueIntegrity(ctx, tx, f.i, "owned", f.result.GoModule.Objects[:1]); e != nil {
						return e
					}
					return appendEvent(ctx, tx, f.i, "fixture.go_latest.queue_seed", map[string]any{"repository": "owned"})
				}); e != nil {
					t.Fatal(e)
				}
				want = ErrQueueFull
			}
			if query != "" {
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			if e = f.s.CompleteRetrieval(ctx, identity, lease, result); !errors.Is(e, want) {
				t.Fatal("latest advertisement crossed common publication fence", scenario, e, want)
			}
			a, b, c := f.counts(t)
			if scenario != "complete" {
				intents := 0
				if scenario == "queue" {
					intents = 1
				}
				if a != 0 || b != intents || c != 0 {
					t.Fatal("failed latest left partial publication", a, b, c)
				}
				return
			}
			if a != 1 || b != 1 || c != 1 {
				t.Fatal("latest reference/integrity/event not atomic", a, b, c)
			}
			stored, e := f.s.ArtifactReference(ctx, f.i, "owned", lease.Path, MaxGoModuleLatestMetadata)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := ValidateGoModuleLatestArtifact(stored); e != nil || got != latest || stored.Decision != "unassessed" {
				t.Fatal("latest lost raw byte binding or granted approval", e)
			}
			if _, e = f.s.Artifact(ctx, f.i, "owned", f.result.GoModule.Objects[0].Path); !errors.Is(e, ErrNotFound) {
				t.Fatal("latest advertisement published package bytes", e)
			}
			updated := []byte(`{"Version":"v1.1.0"}`)
			next, e := NewGoModuleLatest(mod, updated)
			if e != nil {
				t.Fatal(e)
			}
			nextObject, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(updated), "", int64(len(updated)))
			if e != nil {
				t.Fatal(e)
			}
			nextRaw, _ := json.Marshal(next)
			nextLease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", lease.Path, "owned-latest-refresh", true)
			if e != nil || !nextLease.Acquired {
				t.Fatal(e)
			}
			if e = f.s.CompleteRetrieval(ctx, f.i, nextLease, RetrievalResult{Status: 200, Object: &nextObject, MediaType: GoModuleLatestMedia, Metadata: nextRaw, FreshSeconds: 60, GoLatest: &next}); e != nil {
				t.Fatal(e)
			}
			if e = f.s.CompleteRetrieval(ctx, f.i, lease, result); !errors.Is(e, ErrLeaseLost) {
				t.Fatal("old latest lease rewrote current advertisement", e)
			}
			stored, e = f.s.ArtifactReference(ctx, f.i, "owned", lease.Path, MaxGoModuleLatestMetadata)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := ValidateGoModuleLatestArtifact(stored); e != nil || got != next {
				t.Fatal("refresh lost new current coordinate", e)
			}
			original, e := f.objects.OpenVerified(ctx, f.i.Tenant, object.Digest, object.Size)
			if e != nil {
				t.Fatal("refresh changed original staged bytes", e)
			}
			original.Close()
			if a, b, c := f.counts(t); a != 1 || b != 2 || c != 2 {
				t.Fatal("refresh reference/intents/events", a, b, c)
			}
		})
	}
}
