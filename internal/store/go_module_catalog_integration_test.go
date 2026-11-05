//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestGoModuleCatalogPublicationUsesCommonLeaseSourceAndOutbox(t *testing.T) {
	for _, scenario := range []string{"complete", "full-outbox", "source", "lease"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			mod := "go.cratectl.invalid/Owned/intake"
			data := []byte("v1.1.0\r\nv1.0.0\n")
			catalog, e := NewGoModuleCatalog(mod, data, 100, 4096)
			if e != nil {
				t.Fatal(e)
			}
			object, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(data), "", int64(len(data)))
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(catalog)
			result := RetrievalResult{Status: 200, Object: &object, Metadata: raw, MediaType: GoModuleCatalogMedia, FreshSeconds: 60, GoCatalog: &catalog}
			lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleCatalogPath(mod), "owned-go-catalog", false)
			if e != nil || !lease.Acquired {
				t.Fatal("catalog common retrieval fence", e)
			}
			want := error(nil)
			if scenario == "full-outbox" {
				policy := QueuePolicy{Queue: "integrity", Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}
				if _, e = f.s.SetQueuePolicy(ctx, f.i, "catalog-small-queue", "catalog-small-queue", policy); e != nil {
					t.Fatal(e)
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					if e := enqueueIntegrity(ctx, tx, f.i, "owned", f.result.GoModule.Objects[:1]); e != nil {
						return e
					}
					return appendEvent(ctx, tx, f.i, "fixture.go_catalog.queue_seed", map[string]any{"repository": "owned"})
				}); e != nil {
					t.Fatal(e)
				}
				want = ErrQueueFull
			}
			if scenario == "source" || scenario == "lease" {
				query := `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
				want = ErrSourceChanged
				if scenario == "lease" {
					query = `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='owned'`
					want = ErrLeaseLost
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			if e = f.s.CompleteRetrieval(ctx, f.i, lease, result); !errors.Is(e, want) {
				t.Fatal("catalog intake crossed transaction fence", scenario, e, want)
			}
			a, b, c := f.counts(t)
			if scenario == "complete" {
				if a != 1 || b != 1 || c != 1 {
					t.Fatal("catalog reference, integrity intent and event not atomic", a, b, c)
				}
				a, e := f.s.NativeCatalogArtifact(ctx, f.i, "owned", strings.TrimPrefix(lease.Path, "go-catalog/"), "go", GoModuleCatalogMedia)
				if e != nil || a.Decision != "unassessed" {
					t.Fatal("discovery changed package approval", e)
				}
				stored, e := ValidateGoModuleCatalogArtifact(a)
				if e != nil || !slices.Equal(stored.Versions, []string{"v1.0.0", "v1.1.0"}) || a.Digest != object.Digest || a.Size != object.Size {
					t.Fatal("stored catalog lost raw binding/canonical names", e)
				}
				if _, e = f.s.Artifact(ctx, f.i, "owned", f.result.GoModule.Objects[0].Path); !errors.Is(e, ErrNotFound) {
					t.Fatal("catalog advertised names published package bytes", e)
				}
				// A source advertisement is mutable; its original bytes remain
				// immutable, and an old lease cannot replace the new observation.
				nextData := []byte("v1.2.0\nv1.0.0\n")
				nextCatalog, e := NewGoModuleCatalog(mod, nextData, 100, 4096)
				if e != nil {
					t.Fatal(e)
				}
				nextObject, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(nextData), "", int64(len(nextData)))
				if e != nil {
					t.Fatal(e)
				}
				nextLease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", lease.Path, "owned-go-catalog-refresh", true)
				if e != nil || !nextLease.Acquired {
					t.Fatal(e)
				}
				nextRaw, _ := json.Marshal(nextCatalog)
				nextResult := RetrievalResult{Status: 200, Object: &nextObject, Metadata: nextRaw, MediaType: GoModuleCatalogMedia, FreshSeconds: 60, GoCatalog: &nextCatalog}
				if e = f.s.CompleteRetrieval(ctx, f.i, nextLease, nextResult); e != nil {
					t.Fatal("refresh complete source advertisement", e)
				}
				if e = f.s.CompleteRetrieval(ctx, f.i, lease, result); !errors.Is(e, ErrLeaseLost) {
					t.Fatal("old catalog lease replaced current names", e)
				}
				current, e := f.s.NativeCatalogArtifact(ctx, f.i, "owned", strings.TrimPrefix(lease.Path, "go-catalog/"), "go", GoModuleCatalogMedia)
				if e != nil {
					t.Fatal(e)
				}
				view, e := ValidateGoModuleCatalogArtifact(current)
				if e != nil || !slices.Equal(view.Versions, []string{"v1.0.0", "v1.2.0"}) || current.Digest != nextObject.Digest {
					t.Fatal("catalog refresh did not select new exact names", e)
				}
				original, e := f.objects.OpenVerified(ctx, f.i.Tenant, object.Digest, object.Size)
				if e != nil {
					t.Fatal("source refresh changed original immutable list bytes", e)
				}
				original.Close()
				if a, b, c := f.counts(t); a != 1 || b != 2 || c != 2 {
					t.Fatal("refresh references/intents/events", a, b, c)
				}
			} else {
				jobs := 0
				if scenario == "full-outbox" {
					jobs = 1
				}
				if a != 0 || b != jobs || c != 0 {
					t.Fatal("failed catalog left references or publication intents", a, b, c)
				}
				if scenario == "full-outbox" {
					current, e := f.s.Retrieval(ctx, f.i, "owned", lease.Path)
					if e != nil || current.State == "fetching" {
						t.Fatal("queue refusal stranded catalog lease", e)
					}
				}
			}
		})
	}
}
