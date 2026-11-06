//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleLatestDiscoveryUsesCurrentHintInsteadOfCachedPseudoHistory(t *testing.T) {
	for _, scenario := range []string{"cached-newer", "review", "cached-denied", "lower-shadowed", "namespace-pin", "lower-hosted-tag", "zero-age", "zero-without-admission", "negative-known", "negative-unknown", "negative-zero", "missing-hint", "expired-hint", "denied-hint", "stale-hint", "source", "count-budget", "metadata-budget"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			mod := "go.cratectl.invalid/Owned/intake"
			current := "v0.0.0-20260102030405-0123456789ab"
			cached := "v0.0.0-20260103030405-0123456789ab"
			if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET require_review=$1 WHERE name='owned'`, scenario == "review")
				return e
			}); e != nil {
				t.Fatal(e)
			}
			publishProxy := func(version string) {
				t.Helper()
				bundle := f.bundleAt(t, gomodule.Coordinate{Module: mod, Version: version}, "owned cache "+version)
				lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", bundle.GoModule.Objects[0].Path, "owned-pseudo-bundle", false)
				if e != nil || !lease.Acquired {
					t.Fatal(e)
				}
				if e = f.s.CompleteRetrieval(ctx, f.i, lease, bundle); e != nil {
					t.Fatal(e)
				}
			}
			if scenario != "negative-unknown" {
				publishProxy(cached)
			}
			if scenario == "cached-denied" || scenario == "lower-shadowed" {
				publishProxy(current)
				if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned' AND path=$1`, gomodule.Coordinate{Module: mod, Version: current}.Prefix()+".zip")
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			catalog, e := NewGoModuleCatalog(mod, []byte{}, 100, 4096)
			if e != nil {
				t.Fatal(e)
			}
			object, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader([]byte{}), "", 0)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(catalog)
			lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleCatalogPath(mod), "owned-latest-list", false)
			if e != nil || !lease.Acquired {
				t.Fatal(e)
			}
			if e = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Status: 200, Object: &object, MediaType: GoModuleCatalogMedia, Metadata: raw, FreshSeconds: 60, GoCatalog: &catalog}); e != nil {
				t.Fatal(e)
			}
			var admissions []NativeAdmission
			if scenario != "missing-hint" && scenario != "namespace-pin" && scenario != "lower-hosted-tag" {
				data := []byte(`{"Version":"` + current + `"}`)
				hint, e := NewGoModuleLatest(mod, data)
				if e != nil {
					t.Fatal(e)
				}
				object, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(data), "", int64(len(data)))
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(hint)
				h, e := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleLatestPath(mod), "owned-current-hint", false)
				if e != nil || !h.Acquired {
					t.Fatal(e)
				}
				fresh := 60
				if scenario == "zero-age" || scenario == "zero-without-admission" || scenario == "negative-zero" {
					fresh = 0
				}
				result := RetrievalResult{Status: 200, Object: &object, MediaType: GoModuleLatestMedia, Metadata: raw, FreshSeconds: fresh, StaleSeconds: 60, GoLatest: &hint}
				if scenario == "negative-known" || scenario == "negative-unknown" || scenario == "negative-zero" {
					result = RetrievalResult{Status: 404, FreshSeconds: fresh}
				}
				if e = f.s.CompleteRetrieval(ctx, f.i, h, result); e != nil {
					t.Fatal(e)
				}
				if scenario == "zero-age" || scenario == "negative-zero" {
					admissions = append(admissions, NativeAdmission{Repository: "owned", Path: h.Path, Generation: h.Generation})
				}
				if scenario == "stale-hint" {
					h, e = f.s.AcquireRetrieval(ctx, f.i, "owned", h.Path, "owned-hint-outage", true)
					if e != nil || !h.Acquired {
						t.Fatal(e)
					}
					if e = f.s.CompleteRetrieval(ctx, f.i, h, RetrievalResult{Status: 503, Failure: "transient_upstream_failure"}); e != nil {
						t.Fatal(e)
					}
					admissions = append(admissions, NativeAdmission{Repository: "owned", Path: h.Path, Generation: h.Generation, Stale: true})
				}
			}
			repo := "owned"
			if scenario == "lower-shadowed" || scenario == "namespace-pin" || scenario == "lower-hosted-tag" {
				settings := RepositorySettings{Members: []string{"owned", "lower"}}
				if scenario == "namespace-pin" {
					settings.NamespaceOwners = map[string]string{"go.cratectl.invalid/!owned/": "lower"}
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					if e := CreateRepository(ctx, tx, f.i, Repository{Name: "lower", Format: "go", Access: "restricted"}); e != nil {
						return e
					}
					return CreateRepository(ctx, tx, f.i, Repository{Name: "combined", Format: "go", Mode: "group", Settings: settings})
				}); e != nil {
					t.Fatal(e)
				}
				version := current
				if scenario == "lower-hosted-tag" {
					version = "v1.0.0"
				}
				bundle := f.bundleAt(t, gomodule.Coordinate{Module: mod, Version: version}, "lower distinct bytes")
				if _, e = f.s.PublishGoModule(ctx, f.i, "lower", bundle.GoModule.Objects, "owned-lower-latest"); e != nil {
					t.Fatal(e)
				}
				repo = "combined"
			}
			wantVersions := []string{current}
			known := true
			want := error(nil)
			query := ""
			limit, budget := 100, int64(1<<20)
			switch scenario {
			case "review", "cached-denied", "lower-shadowed", "negative-known", "negative-zero":
				wantVersions = []string{}
			case "negative-unknown":
				wantVersions = []string{}
				known = false
			case "lower-hosted-tag":
				wantVersions = []string{"v1.0.0"}
			case "zero-without-admission", "missing-hint":
				want = ErrGoModuleCacheExpired
			case "expired-hint":
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository='owned' AND starts_with(path,'go-latest/')`
				want = ErrGoModuleCacheExpired
			case "denied-hint":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned' AND starts_with(path,'go-latest/')`
				want = ErrDenied
			case "source":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
				want = ErrSourceChanged
			case "count-budget":
				limit = 1
				want = ErrMetadataLimit
			case "metadata-budget":
				budget = 1
				want = ErrMetadataLimit
			}
			if query != "" {
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			view, e := f.s.GoModuleLatestView(ctx, f.i, repo, mod, limit, budget, admissions...)
			if !errors.Is(e, want) {
				t.Fatal("latest hint crossed discovery policy/cache/source/budget boundary", scenario, e, want)
			}
			if want != nil {
				if view.Known || len(view.Versions) != 0 {
					t.Fatal("failed latest discovery returned partial prefix")
				}
				return
			}
			if view.Known != known || !slices.Equal(view.Versions, wantVersions) {
				t.Fatal("latest reused cached pseudo history or bypassed source policy", scenario, view, wantVersions, known)
			}
			if scenario == "cached-newer" || scenario == "negative-known" || scenario == "missing-hint" {
				list, e := f.s.GoModuleView(ctx, f.i, repo, mod, 100, 1<<20)
				if e != nil || !slices.Contains(list.Versions, cached) {
					t.Fatal("ordinary version discovery incorrectly depends on latest hint", e)
				}
			}
		})
	}
}
