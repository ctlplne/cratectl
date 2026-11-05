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

func TestGoModuleCatalogReadUsesCurrentBoundedTypedAdmission(t *testing.T) {
	for _, scenario := range []string{"fresh", "zero-age", "zero-without-admission", "expired", "source", "oversized", "wrong-digest", "denied", "metadata-budget", "negative-expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			mod := "go.cratectl.invalid/Owned/intake"
			data := []byte("v1.0.0\n")
			catalog, e := NewGoModuleCatalog(mod, data, 100, 4096)
			if e != nil {
				t.Fatal(e)
			}
			object, e := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(data), "", int64(len(data)))
			if e != nil {
				t.Fatal(e)
			}
			lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleCatalogPath(mod), "owned-catalog-read", false)
			if e != nil || !lease.Acquired {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(catalog)
			fresh := 60
			if scenario == "zero-age" || scenario == "zero-without-admission" {
				fresh = 0
			}
			result := RetrievalResult{Status: 200, Object: &object, MediaType: GoModuleCatalogMedia, Metadata: raw, FreshSeconds: fresh, GoCatalog: &catalog}
			if scenario == "negative-expired" {
				result = RetrievalResult{Status: 404, FreshSeconds: 0}
			}
			if e = f.s.CompleteRetrieval(ctx, f.i, lease, result); e != nil {
				t.Fatal(e)
			}
			var admissions []NativeAdmission
			if scenario == "zero-age" {
				admissions = []NativeAdmission{{Repository: "owned", Path: lease.Path, Generation: lease.Generation}}
			}
			budget := int64(4096)
			want := error(nil)
			query := ""
			switch scenario {
			case "zero-without-admission", "negative-expired":
				want = ErrGoModuleCacheExpired
			case "expired":
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository='owned'`
				want = ErrGoModuleCacheExpired
			case "source":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
				want = ErrSourceChanged
			case "oversized":
				query = `UPDATE cratectl.artifacts SET metadata=jsonb_build_object('owned_padding',repeat('x',1048576)) WHERE repository='owned'`
				want = ErrMetadataLimit
			case "wrong-digest":
				query = `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{upstream_list_sha256}',to_jsonb(repeat('0',64))) WHERE repository='owned'`
				want = ErrGoModuleUnvalidated
			case "denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned'`
				want = ErrDenied
			case "metadata-budget":
				budget = 1
				want = ErrMetadataLimit
			}
			if query != "" {
				if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			a, e := f.s.GoModuleCatalogArtifact(ctx, f.i, "owned", mod, 0, budget, admissions...)
			if !errors.Is(e, want) {
				t.Fatal("catalog read changed current source/cache/policy/budget boundary", scenario, e, want)
			}
			if want != nil {
				if a.Path != "" || a.Digest != "" || len(a.Metadata) != 0 {
					t.Fatal("rejected catalog exposed partial metadata")
				}
				return
			}
			if a.Path != lease.Path || a.Digest != object.Digest || a.Size != object.Size || a.Decision != "unassessed" {
				t.Fatal("typed advertisement changed bytes or approval")
			}
		})
	}
}
