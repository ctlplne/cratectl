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

func TestGoModuleLatestCallerUsesCurrentMetadataCacheWithoutPackageAdmission(t *testing.T) {
	for _, scenario := range []string{"fresh", "zero-age", "negative", "negative-zero", "refresh", "stale", "hard", "source", "denied", "wrong-generation", "oversized", "missing-reference", "tenant", "grant"} {
		t.Run(scenario, func(t *testing.T) {
			s, d, _, i := schemaServer(t)
			ctx := context.Background()
			c, _ := goOriginBytes(t)
			var calls atomic.Int32
			var phase atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/go/source/"+strings.TrimPrefix(store.GoModuleLatestPath(c.Module), "go-latest/")+"/@latest" {
					t.Error("latest caller escaped source")
					w.WriteHeader(400)
					return
				}
				if scenario == "negative" || scenario == "negative-zero" {
					if scenario == "negative-zero" {
						w.Header().Set("Cache-Control", "no-cache")
					}
					w.WriteHeader(404)
					return
				}
				if phase.Load() != 0 {
					if scenario == "stale" {
						w.WriteHeader(503)
						return
					}
					if scenario == "hard" {
						w.WriteHeader(401)
						return
					}
				}
				if scenario == "zero-age" || scenario == "wrong-generation" {
					w.Header().Set("Cache-Control", "no-cache")
				}
				if phase.Load() != 0 && scenario == "refresh" {
					w.Write([]byte(`{"Version":"v1.1.0"}`))
					return
				}
				w.Write([]byte(`{"Version":"v1.0.0"}`))
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60, NegativeSeconds: 30, RequireChecksum: true}, true)
			p := store.GoModuleLatestPath(c.Module)
			a, e := s.resolve(ctx, i, repo, p, false)
			if scenario == "negative" || scenario == "negative-zero" {
				if !errors.Is(e, store.ErrNotFound) || a.artifact.Digest != "" {
					t.Fatal("missing optional hint became a package", e)
				}
				goCallerCounts(t, s, i, 0)
				if scenario == "negative-zero" {
					if _, e = s.DB.GoModuleLatestArtifact(ctx, i, repo.Name, c.Module, repo.SourceRevision, 1<<20); !errors.Is(e, store.ErrGoModuleCacheExpired) {
						t.Fatal("negative-zero hint escaped request admission", e)
					}
				}
				return
			}
			if e != nil || a.artifact.Decision != "unassessed" {
				t.Fatal("latest caller lost metadata/approval separation", e)
			}
			if got, e := store.ValidateGoModuleLatestArtifact(a.artifact); e != nil || got.Version != "v1.0.0" {
				t.Fatal("caller returned unbound latest hint", e)
			}
			identity := i
			want := error(nil)
			query := ""
			switch scenario {
			case "zero-age":
				a.admissions = nil
				want = store.ErrGoModuleCacheExpired
			case "wrong-generation":
				a.admissions[0].Generation++
				want = store.ErrGoModuleCacheExpired
			case "source":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`
				want = store.ErrSourceChanged
			case "denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='source'`
				want = store.ErrDenied
			case "oversized":
				query = `UPDATE cratectl.artifacts SET metadata=jsonb_build_object('padding',repeat('x',1048576)) WHERE repository='source'`
				want = store.ErrMetadataLimit
			case "missing-reference":
				d.ExecDeleteFault(t, i.Tenant, `DELETE FROM cratectl.artifacts WHERE repository='source'`)
				want = store.ErrGoModuleUnvalidated
			case "tenant":
				identity = store.Identity{Tenant: "other-owned-tenant", Actor: "operator", Role: "admin"}
				want = store.ErrNotFound
			case "grant":
				identity = store.Identity{Tenant: i.Tenant, Actor: "ungranted-latest-reader", Role: "reader"}
				want = store.ErrDenied
			}
			if query != "" {
				if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "refresh" || scenario == "stale" || scenario == "hard" {
				phase.Store(1)
				a, e = s.resolve(ctx, i, repo, p, true)
				if scenario == "hard" {
					if !errors.Is(e, errUpstream) || a.artifact.Digest != "" {
						t.Fatal("hard origin failure admitted stale hint", e)
					}
					goCallerCounts(t, s, i, 1)
					return
				}
				if e != nil {
					t.Fatal("current hint refresh", e)
				}
				if scenario == "stale" && a.cache != "stale" {
					t.Fatal("temporary origin failure lost explicit stale admission")
				}
				if scenario == "refresh" {
					if got, e := store.ValidateGoModuleLatestArtifact(a.artifact); e != nil || got.Version != "v1.1.0" {
						t.Fatal("latest refresh reused previous coordinate", e)
					}
				}
			}
			current, e := s.DB.GoModuleLatestArtifact(ctx, identity, repo.Name, c.Module, repo.SourceRevision, 1<<20, a.admissions...)
			if !errors.Is(e, want) {
				t.Fatal("latest hint ignored current cache/source/policy/grant boundary", scenario, e, want)
			}
			if want != nil {
				if current.Digest != "" || len(current.Metadata) != 0 {
					t.Fatal("rejected hint exposed partial metadata")
				}
				return
			}
			if current.Digest != a.artifact.Digest {
				t.Fatal("current hint changed original response binding")
			}
			if scenario == "fresh" {
				if _, e = s.resolve(ctx, i, repo, p, false); e != nil || calls.Load() != 1 {
					t.Fatal("fresh hint did not reuse current receipt", e, calls.Load())
				}
			}
			if _, e = s.DB.Artifact(ctx, i, repo.Name, c.Prefix()+".zip"); !errors.Is(e, store.ErrNotFound) {
				t.Fatal("hint caller published a package", e)
			}
			intents := 1
			if scenario == "refresh" {
				intents = 2
			}
			goCallerCounts(t, s, i, 1, intents)
		})
	}
}
