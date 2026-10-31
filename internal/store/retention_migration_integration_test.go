//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"testing"

	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRetentionMigrationPreservesSixReceiptsAndForcesTenantEvidenceIsolation(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:6]); e != nil {
		t.Fatal(e)
	}
	before, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(before.Applied) != 6 || len(before.Pending) != len(steps)-6 || before.Pending[0] != 7 || !before.SafetyValid {
		t.Fatal(before, e)
	}
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:6], true); e != nil {
		t.Fatal("schema-six runtime rejected before controlled maintenance", e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	after, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(after.Applied) != len(steps) || len(after.Pending) != 0 || !after.SafetyValid {
		t.Fatal(after, e)
	}
	for n, r := range before.Applied {
		if after.Applied[n] != r {
			t.Fatal("frozen migration receipt changed", n)
		}
	}
	if e = checkSchemaPlan(ctx, runtime, steps[:6], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted retention schema", e)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	for _, table := range []string{"retention_policies", "retention_revisions", "retention_runs", "retention_items", "retention_observations"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		if _, e = owner.Exec(ctx, `ALTER TABLE `+q+` NO FORCE ROW LEVEL SECURITY`); e != nil {
			t.Fatal(e)
		}
		if e = checkSchema(ctx, runtime, true); !errors.Is(e, ErrSchemaIncompatible) {
			t.Fatal("unsafe retention table admitted", table, e)
		}
		if _, e = owner.Exec(ctx, `ALTER TABLE `+q+` FORCE ROW LEVEL SECURITY`); e != nil {
			t.Fatal(e)
		}
		if table != "retention_policies" {
			_, e = runtime.Exec(ctx, `DELETE FROM `+q+` WHERE false`)
			var pe *pgconn.PgError
			if !errors.As(e, &pe) || pe.Code != "42501" {
				t.Fatal("runtime can delete immutable retention evidence", table, e)
			}
			_, e = runtime.Exec(ctx, `UPDATE `+q+` SET tenant=tenant WHERE false`)
			if !errors.As(e, &pe) || pe.Code != "42501" {
				t.Fatal("runtime can rewrite immutable retention evidence", table, e)
			}
		}
	}
	if e = checkSchema(ctx, runtime, true); e != nil {
		t.Fatal(e)
	}
	t.Logf("migration seven checksum: %s", after.Applied[6].Checksum)
}
