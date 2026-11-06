//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestGoModuleChecksumPolicyRejectsUnfencedPublicationAndCachedBytes(t *testing.T) {
	for _, scenario := range []string{"publication-required", "publication-configured", "cache-required", "cache-configured"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			cached := strings.HasPrefix(scenario, "cache-")
			if cached {
				if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
					t.Fatal(err)
				}
				if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='owned'`)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, f.lease.SourceRevision); err != nil {
					t.Fatal("prove original complete cached bytes are readable before trust change", err)
				}
			}
			authority, _, _ := checksumPublicFixture(t)
			patch := map[string]any{"cache": CacheSettings{FreshSeconds: 60, StaleSeconds: 60, RequireChecksum: strings.HasSuffix(scenario, "required")}}
			if strings.HasSuffix(scenario, "configured") {
				patch["go_checksum_authority"] = authority
			}
			raw, err := json.Marshal(patch)
			if err != nil {
				t.Fatal(err)
			}
			// Deliberate owned-row fault without an epoch change proves the
			// checksum guard itself; ordinary configuration also fences epochs.
			if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE cratectl.repositories SET settings=settings||$1::jsonb WHERE name='owned'`, raw)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if cached {
				out, err := f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, f.lease.SourceRevision)
				if !errors.Is(err, ErrGoModuleUnvalidated) || !reflect.DeepEqual(out, Artifact{}) {
					t.Fatal("previous bytes bypassed current independent-checksum admission", err)
				}
			} else {
				if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); !errors.Is(err, ErrGoModuleUnvalidated) {
					t.Fatal("unfenced checkpoint/proof publication admitted", err)
				}
				if refs, integrity, ready := f.counts(t); refs != 0 || integrity != 0 || ready != 0 {
					t.Fatal("rejected trust policy left partial references, work or ready event", refs, integrity, ready)
				}
			}
		})
	}
}
