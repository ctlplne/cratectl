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
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleDiscoveryUsesCurrentCatalogPolicyPrecedenceAndBudgets(t *testing.T) {
	for _, scenario := range []string{"catalog", "require-review", "denied-first", "group-review", "namespace-pin", "missing-catalog", "expired", "zero-age", "negative", "catalog-denied", "source", "metadata-budget", "count-budget", "grant", "tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			mod := "go.cratectl.invalid/Owned/intake"
			data := []byte("v1.0.0\nv1.1.0\n")
			catalog, e := NewGoModuleCatalog(mod, data, 10, 4096)
			if e != nil {
				t.Fatal(e)
			}
			object, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(data), "", int64(len(data)))
			if e != nil {
				t.Fatal(e)
			}
			lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleCatalogPath(mod), "owned-discovery", false)
			if e != nil || !lease.Acquired {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(catalog)
			fresh := 60
			if scenario == "zero-age" {
				fresh = 0
			}
			if e = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Status: 200, Object: &object, Metadata: raw, MediaType: GoModuleCatalogMedia, GoCatalog: &catalog, FreshSeconds: fresh}); e != nil {
				t.Fatal(e)
			}
			if scenario != "require-review" {
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET require_review=false WHERE name='owned'`)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			repo := "owned"
			identity := f.i
			wantVersions := []string{"v1.0.0", "v1.1.0"}
			wantKnown := true
			want := error(nil)
			limit, budget := 100, int64(1<<20)
			admissions := []NativeAdmission{}
			if scenario == "denied-first" || scenario == "group-review" || scenario == "namespace-pin" || scenario == "negative" {
				settings := RepositorySettings{Members: []string{"owned", "lower"}}
				if scenario == "namespace-pin" {
					settings.NamespaceOwners = map[string]string{"go.cratectl.invalid/!owned/": "lower"}
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					if e := CreateRepository(ctx, tx, f.i, Repository{Name: "lower", Format: "go", Access: "restricted"}); e != nil {
						return e
					}
					return CreateRepository(ctx, tx, f.i, Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", RequireReview: scenario == "group-review", Settings: settings})
				}); e != nil {
					t.Fatal(e)
				}
				if _, e = f.s.PublishGoModule(ctx, f.i, "lower", f.result.GoModule.Objects, "lower-discovery"); e != nil {
					t.Fatal(e)
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='lower'`)
					return e
				}); e != nil {
					t.Fatal(e)
				}
				repo = "combined"
			}
			query := ""
			switch scenario {
			case "require-review", "group-review":
				wantVersions = []string{}
			case "denied-first":
				if e = f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); e != nil {
					t.Fatal(e)
				}
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned' AND ends_with(path,'.zip')`
				wantVersions = []string{"v1.1.0"}
			case "namespace-pin":
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch' WHERE repository='owned'`
				wantVersions = []string{"v1.0.0"}
			case "missing-catalog":
				query = `DELETE FROM cratectl.artifacts WHERE repository='owned' AND starts_with(path,'go-catalog/')`
				want = ErrGoModuleUnvalidated
			case "expired":
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch' WHERE repository='owned'`
				want = ErrGoModuleCacheExpired
			case "zero-age":
				if _, e = f.s.GoModuleView(ctx, identity, repo, mod, limit, budget); !errors.Is(e, ErrGoModuleCacheExpired) {
					t.Fatal("zero-age catalog admitted later discovery", e)
				}
				admissions = []NativeAdmission{{Repository: "owned", Path: lease.Path, Generation: lease.Generation}}
			case "negative":
				current, e := f.s.AcquireRetrieval(ctx, f.i, "owned", lease.Path, "owned-catalog-absent", true)
				if e != nil || !current.Acquired {
					t.Fatal(e)
				}
				if e = f.s.CompleteRetrieval(ctx, f.i, current, RetrievalResult{Status: 404, FreshSeconds: 60}); e != nil {
					t.Fatal(e)
				}
				wantVersions = []string{"v1.0.0"}
			case "catalog-denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned'`
				want = ErrDenied
			case "source":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
				want = ErrSourceChanged
			case "metadata-budget":
				budget = 128
				want = ErrMetadataLimit
			case "count-budget":
				limit = 1
				want = ErrMetadataLimit
			case "grant", "tenant":
				token, e := crypt.Token()
				if e != nil {
					t.Fatal(e)
				}
				tenant, role := f.i.Tenant, "reader"
				if scenario == "tenant" {
					tenant, role = "other-discovery-team", "admin"
				}
				if e = Provision(ctx, f.d.OwnerDSN, tenant, "discovery-reader", role, token, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				identity, e = f.s.Authenticate(ctx, token)
				if e != nil {
					t.Fatal(e)
				}
				if scenario == "tenant" {
					settings, _ := json.Marshal(RepositorySettings{})
					if e = f.s.Tx(ctx, identity, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings)VALUES($1,'owned','go','proxy',false,'restricted',$2)`, identity.Tenant, settings)
						return e
					}); e != nil {
						t.Fatal(e)
					}
					want = ErrGoModuleCacheExpired
				} else {
					if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'owned','discovery-reader',true,false)`, f.i.Tenant)
						return e
					}); e != nil {
						t.Fatal(e)
					}
					if view, e := f.s.GoModuleView(ctx, identity, repo, mod, limit, budget); e != nil || len(view.Versions) != 2 {
						t.Fatal("granted reader could not discover source", e)
					}
					query = `UPDATE cratectl.repository_grants SET can_read=false WHERE repository='owned' AND actor='discovery-reader'`
					want = ErrDenied
				}
			}
			if query != "" {
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			view, e := f.s.GoModuleView(ctx, identity, repo, mod, limit, budget, admissions...)
			if !errors.Is(e, want) {
				t.Fatal("current discovery authority/budget", scenario, e, want)
			}
			if e != nil {
				if len(view.Versions) != 0 || view.Known {
					t.Fatal("failed discovery returned partial source names", scenario)
				}
			} else if !slices.Equal(view.Versions, wantVersions) || view.Known != wantKnown {
				t.Fatal("source catalog replaced current policy/precedence", scenario, view)
			}
			if scenario == "catalog" {
				// A direct proxy advertisement still has no package bytes. This
				// metadata view does not create a bundle or approve unknown scans.
				for _, a := range f.result.GoModule.Objects {
					if _, e = f.s.Artifact(ctx, f.i, "owned", a.Path); !errors.Is(e, ErrNotFound) {
						t.Fatal("discovery served unadmitted package", e)
					}
				}
			}
		})
	}
}
