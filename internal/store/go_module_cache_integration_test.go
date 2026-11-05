//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleCacheAdmissionRequiresCurrentWholeBundle(t *testing.T) {
	for _, scenario := range []string{"fresh", "unassessed", "sibling-denied", "missing-receipt", "missing-sibling", "missing-all-references", "wrong-root", "wrong-generation", "expired", "max-age-zero", "fetching", "negative", "stale-transient", "stale-authority", "stale-generation", "source", "grant", "tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			if scenario == "fresh" && f.lease.SourceRevision != 0 {
				t.Fatal("initial source epoch regression must exercise the schema's zero revision")
			}
			ctx := context.Background()
			if scenario == "max-age-zero" {
				f.result.FreshSeconds = 0
			}
			if e := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); e != nil {
				t.Fatal(e)
			}
			if scenario != "unassessed" {
				if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='owned'`)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			want := error(nil)
			identity := f.i
			admissions := []NativeAdmission{}
			query := ""
			switch scenario {
			case "unassessed":
				want = ErrDenied
			case "sibling-denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned' AND right(path,5)='.info'`
				want = ErrDenied
			case "missing-receipt":
				query = `DELETE FROM cratectl.retrievals WHERE repository='owned' AND right(path,4)='.mod'`
				want = ErrGoModuleCacheExpired
			case "missing-sibling":
				query = `DELETE FROM cratectl.artifacts WHERE repository='owned' AND right(path,4)='.mod'`
				want = ErrGoModuleUnvalidated
			case "missing-all-references":
				query = `DELETE FROM cratectl.artifacts WHERE repository='owned'`
				want = ErrGoModuleUnvalidated
			case "wrong-root":
				query = `UPDATE cratectl.retrievals SET validation_root='other' WHERE repository='owned' AND right(path,4)='.mod'`
				want = ErrGoModuleUnvalidated
			case "wrong-generation":
				query = `UPDATE cratectl.retrievals SET validation_generation=validation_generation+1 WHERE repository='owned' AND right(path,4)='.mod'`
				want = ErrGoModuleUnvalidated
			case "expired":
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch' WHERE repository='owned'`
				want = ErrGoModuleCacheExpired
			case "source":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
				want = ErrSourceChanged
			case "max-age-zero":
				for _, a := range f.result.GoModule.Objects {
					if _, e := f.s.GoModuleProxyArtifact(ctx, identity, "owned", a.Path, f.lease.SourceRevision); !errors.Is(e, ErrGoModuleCacheExpired) {
						t.Fatal("zero max-age admitted a later request", e)
					}
				}
				admissions = []NativeAdmission{{Repository: "owned", Path: f.lease.Path, Generation: f.lease.Generation}}
			case "fetching", "negative", "stale-transient", "stale-authority", "stale-generation":
				lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "owned-cache-refresh", true)
				if e != nil || !lease.Acquired {
					t.Fatal("acquire refresh attempt", e)
				}
				want = ErrBusy
				if scenario != "fetching" {
					result := RetrievalResult{Failure: "transient_upstream_failure"}
					switch scenario {
					case "negative":
						result = RetrievalResult{Status: 404, FreshSeconds: 60}
						want = ErrDenied
					case "stale-authority":
						result.Failure = "upstream_authority_failure"
						want = ErrGoModuleCacheExpired
					default:
						want = nil
					}
					if e = f.s.CompleteRetrieval(ctx, f.i, lease, result); e != nil {
						t.Fatal(e)
					}
					if scenario != "negative" {
						admissions = []NativeAdmission{{Repository: "owned", Path: lease.Path, Generation: lease.Generation, Stale: true}}
						if scenario == "stale-generation" {
							admissions[0].Generation--
							want = ErrGoModuleCacheExpired
						}
					}
					if scenario == "stale-transient" {
						if _, e = f.s.GoModuleProxyArtifact(ctx, identity, "owned", f.lease.Path, f.lease.SourceRevision); !errors.Is(e, ErrGoModuleCacheExpired) {
							t.Fatal("stale bundle admitted without this request's validation", e)
						}
					}
				}
			case "grant", "tenant":
				token, e := crypt.Token()
				if e != nil {
					t.Fatal(e)
				}
				tenant := f.i.Tenant
				if scenario == "tenant" {
					tenant = "other-cache-team"
				}
				if e = Provision(ctx, f.d.OwnerDSN, tenant, "cache-reader", "reader", token, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				identity, e = f.s.Authenticate(ctx, token)
				if e != nil {
					t.Fatal(e)
				}
				want = ErrNotFound
				if scenario == "grant" {
					if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'owned','cache-reader',true,false)`, f.i.Tenant)
						return e
					}); e != nil {
						t.Fatal(e)
					}
					if _, e = f.s.GoModuleProxyArtifact(ctx, identity, "owned", f.lease.Path, f.lease.SourceRevision); e != nil {
						t.Fatal("granted reader could not read approved bundle", e)
					}
					query = `UPDATE cratectl.repository_grants SET can_read=false WHERE repository='owned' AND actor='cache-reader'`
					want = ErrDenied
				}
			}
			if query != "" {
				if strings.HasPrefix(query, "DELETE FROM ") {
					f.d.ExecDeleteFault(t, f.i.Tenant, query)
				} else if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			for _, a := range f.result.GoModule.Objects {
				got, e := f.s.GoModuleProxyArtifact(ctx, identity, "owned", a.Path, f.lease.SourceRevision, admissions...)
				if !errors.Is(e, want) {
					t.Fatal("current bundle cache/authority admission", scenario, e, want)
				}
				if e == nil && (got.Digest != a.Digest || got.Size != a.Size) {
					t.Fatal("admission changed exact bundle bytes")
				}
				if e != nil && (got.Digest != "" || len(got.Metadata) != 0) {
					t.Fatal("rejected admission returned artifact metadata")
				}
			}
		})
	}
}
