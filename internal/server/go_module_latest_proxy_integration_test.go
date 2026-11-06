//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleOriginLatestPublicationUsesCurrentTransactionFences(t *testing.T) {
	for _, scenario := range []string{"complete", "source", "lease"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			ctx := context.Background()
			c, _ := goOriginBytes(t)
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/go/source/"+strings.TrimPrefix(store.GoModuleLatestPath(c.Module), "go-latest/")+"/@latest" {
					t.Error("latest escaped canonical configured source")
					w.WriteHeader(400)
					return
				}
				if scenario != "complete" {
					query := `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`
					if scenario == "lease" {
						query = `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='source'`
					}
					if e := s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
						t.Error(e)
						w.WriteHeader(500)
						return
					}
				}
				w.Write([]byte("{\n \"Version\":\"v0.0.0-20260102030405-0123456789ab\"\n}\n"))
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, RequireChecksum: true}, true)
			lease, e := s.DB.AcquireRetrieval(ctx, i, repo.Name, store.GoModuleLatestPath(c.Module), "owned-latest-network", false)
			if e != nil || !lease.Acquired {
				t.Fatal(e)
			}
			result, e := s.fetchGoModuleLatest(ctx, i, repo, lease)
			if e != nil || result.GoLatest == nil || calls.Load() != 1 {
				t.Fatal("fetch owned latest advertisement", e)
			}
			want := error(nil)
			n := 1
			if scenario == "source" {
				want, n = store.ErrSourceChanged, 0
			}
			if scenario == "lease" {
				want, n = store.ErrLeaseLost, 0
			}
			if e = s.DB.CompleteRetrieval(ctx, i, lease, result); !errors.Is(e, want) {
				t.Fatal("network latest crossed completion fence", e, want)
			}
			goCallerCounts(t, s, i, n)
			if scenario == "complete" {
				a, e := s.DB.ArtifactReference(ctx, i, repo.Name, lease.Path, store.MaxGoModuleLatestMetadata)
				if e != nil {
					t.Fatal(e)
				}
				if got, e := store.ValidateGoModuleLatestArtifact(a); e != nil || got != *result.GoLatest || a.Decision != "unassessed" {
					t.Fatal("latest advertisement lost coordinate/raw binding or approval separation", e)
				}
				if _, e = s.DB.Artifact(ctx, i, repo.Name, c.Prefix()+".zip"); !errors.Is(e, store.ErrNotFound) {
					t.Fatal("latest network hint published a package", e)
				}
			}
		})
	}
}
