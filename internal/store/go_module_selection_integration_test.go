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

func TestGoModuleFinalSelectionRechecksGroupAuthorityAndExactAbsence(t *testing.T) {
	for _, scenario := range []string{"hosted-stable", "hosted-new-allowed", "hosted-new-denied", "hosted-new-partial", "lower-unread", "group-epoch", "wrong-group-snapshot", "source-epoch", "group-review", "lower-lost", "proxy-missing", "proxy-in-progress", "proxy-negative", "proxy-negative-zero", "proxy-negative-expired", "proxy-negative-known", "proxy-negative-lost", "proxy-fresh", "proxy-unassessed", "proxy-stale", "proxy-stale-authority", "wrong-negative-marker"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			proxy := strings.HasPrefix(scenario, "proxy-") || scenario == "wrong-negative-marker"
			first := "higher"
			if proxy {
				first = "owned"
			}
			if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
				if e := CreateRepository(ctx, tx, f.i, Repository{Name: "lower", Format: "go", Access: "restricted"}); e != nil {
					return e
				}
				if !proxy {
					if e := CreateRepository(ctx, tx, f.i, Repository{Name: "higher", Format: "go", Access: "restricted"}); e != nil {
						return e
					}
				}
				return CreateRepository(ctx, tx, f.i, Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", Settings: RepositorySettings{Members: []string{first, "lower"}}})
			}); e != nil {
				t.Fatal(e)
			}
			if _, e := f.s.PublishGoModule(ctx, f.i, "lower", f.result.GoModule.Objects, "lower-final-selection"); e != nil {
				t.Fatal(e)
			}
			lower, e := f.s.Repository(ctx, f.i, "lower")
			if e != nil {
				t.Fatal(e)
			}
			group, e := f.s.Repository(ctx, f.i, "combined")
			if e != nil {
				t.Fatal(e)
			}
			snapshot := SourceSnapshot{Repository: "lower", Revision: lower.SourceRevision, Groups: map[string]int64{"combined": group.SourceRevision}}
			want := error(nil)
			identity := f.i
			wantSource := "lower"
			admissions := []NativeAdmission{}
			query := ""
			if strings.HasPrefix(scenario, "hosted-new-") {
				if _, e = f.s.PublishGoModule(ctx, f.i, "higher", f.result.GoModule.Objects, "higher-final-selection"); e != nil {
					t.Fatal(e)
				}
				want = ErrConflict
				if scenario == "hosted-new-denied" {
					query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='higher' AND right(path,4)='.zip'`
					want = ErrDenied
				}
				if scenario == "hosted-new-partial" {
					query = `DELETE FROM cratectl.artifacts WHERE repository='higher' AND right(path,5)='.info'`
					want = ErrGoModuleUnvalidated
				}
			}
			switch scenario {
			case "lower-unread":
				if _, e = f.s.PublishGoModule(ctx, f.i, "higher", f.result.GoModule.Objects, "higher-readable"); e != nil {
					t.Fatal(e)
				}
				higher, e := f.s.Repository(ctx, f.i, "higher")
				if e != nil {
					t.Fatal(e)
				}
				snapshot.Repository, snapshot.Revision = "higher", higher.SourceRevision
				wantSource = "higher"
				token, e := crypt.Token()
				if e != nil {
					t.Fatal(e)
				}
				if e = Provision(ctx, f.d.OwnerDSN, f.i.Tenant, "selection-reader", "reader", token, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				identity, e = f.s.Authenticate(ctx, token)
				if e != nil {
					t.Fatal(e)
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'combined','selection-reader',true,false),($1,'higher','selection-reader',true,false)`, f.i.Tenant)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			case "group-epoch":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='combined'`
				want = ErrSourceChanged
			case "wrong-group-snapshot":
				snapshot.Groups = map[string]int64{"other-group": group.SourceRevision}
				want = ErrSourceChanged
			case "source-epoch":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='lower'`
				want = ErrSourceChanged
			case "group-review":
				query = `UPDATE cratectl.repositories SET require_review=true WHERE name='combined'`
				want = ErrDenied
			case "lower-lost":
				query = `DELETE FROM cratectl.artifacts WHERE repository='lower'`
				want = ErrConflict
			case "proxy-missing":
				query = `DELETE FROM cratectl.retrievals WHERE repository='owned'`
				want = ErrGoModuleCacheExpired
			case "proxy-in-progress":
				want = ErrBusy
			case "proxy-negative", "proxy-negative-zero", "proxy-negative-expired", "wrong-negative-marker":
				fresh := 60
				if scenario == "proxy-negative-zero" {
					fresh = 0
				}
				if e = f.s.CompleteRetrieval(ctx, f.i, f.lease, RetrievalResult{Status: 404, FreshSeconds: fresh}); e != nil {
					t.Fatal(e)
				}
				if scenario == "proxy-negative-zero" {
					if _, _, e = f.s.GoModuleSelectionAtRevision(ctx, identity, "combined", f.lease.Path, snapshot); !errors.Is(e, ErrGoModuleCacheExpired) {
						t.Fatal("old no-cache absence authorized fallback", e)
					}
					admissions = []NativeAdmission{{Repository: "owned", Path: f.lease.Path, Generation: f.lease.Generation}}
				}
				if scenario == "proxy-negative-expired" {
					query = `UPDATE cratectl.retrievals SET fresh_until='epoch' WHERE repository='owned'`
					want = ErrGoModuleCacheExpired
				}
				if scenario == "wrong-negative-marker" {
					query = `UPDATE cratectl.retrievals SET last_status=200 WHERE repository='owned'`
					want = ErrGoModuleUnvalidated
				}
			case "proxy-negative-known", "proxy-negative-lost", "proxy-fresh", "proxy-unassessed", "proxy-stale", "proxy-stale-authority":
				if e = f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); e != nil {
					t.Fatal(e)
				}
				if scenario == "proxy-unassessed" {
					want = ErrDenied
					break
				}
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='owned'`)
					return e
				}); e != nil {
					t.Fatal(e)
				}
				owned, e := f.s.Repository(ctx, f.i, "owned")
				if e != nil {
					t.Fatal(e)
				}
				snapshot.Repository, snapshot.Revision = "owned", owned.SourceRevision
				wantSource = "owned"
				if scenario != "proxy-fresh" {
					lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "owned-final-refresh", true)
					if e != nil || !lease.Acquired {
						t.Fatal(e)
					}
					result := RetrievalResult{Failure: "transient_upstream_failure"}
					if strings.HasPrefix(scenario, "proxy-negative-") {
						result = RetrievalResult{Status: 404, FreshSeconds: 60}
						want = ErrDenied
					}
					if scenario == "proxy-negative-lost" {
						query = `DELETE FROM cratectl.artifacts WHERE repository='owned'`
						want = ErrGoModuleUnvalidated
					}
					if scenario == "proxy-stale-authority" {
						result.Failure = "upstream_authority_failure"
						want = ErrGoModuleCacheExpired
					}
					if e = f.s.CompleteRetrieval(ctx, f.i, lease, result); e != nil {
						t.Fatal(e)
					}
					admissions = []NativeAdmission{{Repository: "owned", Path: lease.Path, Generation: lease.Generation, Stale: true}}
				}
			}
			if query != "" {
				if strings.HasPrefix(query, "DELETE FROM ") {
					f.d.ExecDeleteFault(t, f.i.Tenant, query)
				} else if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			for _, original := range f.result.GoModule.Objects {
				a, source, e := f.s.GoModuleSelectionAtRevision(ctx, identity, "combined", original.Path, snapshot, admissions...)
				if !errors.Is(e, want) {
					t.Fatal("final source/policy/cache selection", scenario, e, want)
				}
				if e == nil && (source.Name != wantSource || a.Digest != original.Digest) {
					t.Fatal("final selection changed source or bytes", scenario, source.Name)
				}
				if e != nil && (a.Digest != "" || len(a.Metadata) != 0 || source.Name != "") {
					t.Fatal("rejected final selection disclosed metadata", scenario)
				}
			}
		})
	}
}
