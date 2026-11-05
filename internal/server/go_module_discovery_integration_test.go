//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModulePreparationUsesCompleteCurrentSourceCatalogs(t *testing.T) {
	for _, scenario := range []string{"proxy", "group", "review", "group-review", "namespace-pin", "negative-zero", "invalid", "count-budget", "byte-budget", "stale", "source-change", "grant", "tenant", "catalog-denied"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, token, admin := schemaServer(t)
			ctx := context.Background()
			c, files := goOriginBytes(t)
			var calls atomic.Int32
			var outage atomic.Bool
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if outage.Load() {
					w.WriteHeader(503)
					return
				}
				if r.URL.Path != "/go/source/"+strings.TrimPrefix(store.GoModuleCatalogPath(c.Module), "go-catalog/")+"/@v/list" {
					t.Error("metadata escaped canonical source")
					w.WriteHeader(400)
					return
				}
				if scenario == "negative-zero" {
					w.Header().Set("Cache-Control", "no-cache")
					w.WriteHeader(404)
					return
				}
				if scenario == "invalid" {
					w.Write([]byte("v1.0.0\ninvalid\n"))
					return
				}
				if scenario == "source-change" {
					if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`)
						return e
					}); e != nil {
						t.Error(e)
						w.WriteHeader(500)
						return
					}
				}
				w.Write([]byte("v1.1.0\nv1.0.0\n"))
			}))
			proxy := goCallerRepository(t, s, admin, origin.URL, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60, NegativeSeconds: 30}, scenario == "review")
			settings := store.RepositorySettings{Members: []string{"source", "lower"}}
			if scenario == "namespace-pin" {
				settings.NamespaceOwners = map[string]string{strings.TrimPrefix(store.GoModuleCatalogPath(c.Module), "go-catalog/") + "/": "lower"}
			}
			mavenRepositories(t, s, admin, store.Repository{Name: "lower", Format: "go", Access: "restricted"}, store.Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", RequireReview: scenario == "group-review", Settings: settings})
			if w := goHTTP(t, s, token, "PUT", "/go/lower/"+c.Prefix()+".zip", files["zip"]); w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			repo := proxy
			if scenario != "proxy" {
				var e error
				repo, e = s.DB.Repository(ctx, admin, "combined")
				if e != nil {
					t.Fatal(e)
				}
			}
			i := admin
			if scenario == "grant" {
				i = store.Identity{Tenant: admin.Tenant, Actor: "metadata-reader", Role: "reader"}
				if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)SELECT $1,n,'metadata-reader',true,false FROM unnest(ARRAY['source','combined'])n`, admin.Tenant)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "tenant" {
				i = store.Identity{Tenant: "other-owned-tenant", Actor: "operator", Role: "admin"}
			}
			if scenario == "byte-budget" {
				s.NativeMetadataBytes = 191
			}
			if scenario == "count-budget" || scenario == "stale" || scenario == "catalog-denied" {
				if _, _, e := s.prepareGoModuleView(ctx, admin, repo, c.Module, false); e != nil {
					t.Fatal("prime owned catalog", e)
				}
				if scenario == "count-budget" {
					s.NativeVersionLimit = 1
				}
				if scenario == "stale" {
					outage.Store(true)
				}
				if scenario == "catalog-denied" {
					if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='source'`)
						return e
					}); e != nil {
						t.Fatal(e)
					}
				}
			}
			view, admissions, e := s.prepareGoModuleView(ctx, i, repo, c.Module, scenario == "stale")
			want := error(nil)
			switch scenario {
			case "invalid":
				want = errUpstream
			case "count-budget", "byte-budget":
				want = store.ErrMetadataLimit
			case "source-change":
				want = store.ErrSourceChanged
			case "grant", "catalog-denied":
				want = store.ErrDenied
			case "tenant":
				want = store.ErrNotFound
			}
			if want != nil {
				if !errors.Is(e, want) || len(view.Versions) != 0 || view.Known || len(admissions) != 0 {
					t.Fatal("failed metadata returned partial source prefix", scenario, e, want)
				}
				if (scenario == "grant" || scenario == "tenant" || scenario == "byte-budget") && calls.Load() != 0 {
					t.Fatal("metadata fetched before complete grant/tenant admission")
				}
				return
			}
			versions := []string{"v1.0.0", "v1.1.0"}
			if scenario == "review" || scenario == "group-review" {
				versions = []string{}
			}
			if scenario == "namespace-pin" || scenario == "negative-zero" {
				versions = []string{"v1.0.0"}
			}
			if e != nil || !view.Known || !slices.Equal(view.Versions, versions) {
				t.Fatal("complete metadata changed precedence/review", scenario, e, view)
			}
			if scenario == "namespace-pin" && calls.Load() != 0 {
				t.Fatal("metadata ignored canonical namespace owner")
			}
			current, e := s.DB.GoModuleView(ctx, i, repo.Name, c.Module, s.NativeVersionLimit, s.NativeMetadataBytes, admissions...)
			if e != nil || current.Known != view.Known || !slices.Equal(current.Versions, view.Versions) {
				t.Fatal("current metadata guard lost preparation admissions", e)
			}
			if scenario == "negative-zero" {
				if _, e = s.DB.GoModuleView(ctx, i, repo.Name, c.Module, s.NativeVersionLimit, s.NativeMetadataBytes); !errors.Is(e, store.ErrGoModuleCacheExpired) {
					t.Fatal("no-cache absence escaped this metadata request", e)
				}
			}
		})
	}
}
