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

func TestRetentionScheduleMigrationPreservesSevenReceiptsAndGuardsTenantTables(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:7]); e != nil {
		t.Fatal(e)
	}
	before, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(before.Applied) != 7 || len(before.Pending) != len(steps)-7 || before.Pending[0] != 8 || !before.SafetyValid {
		t.Fatal("seven-step baseline", e)
	}
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:7], true); e != nil {
		t.Fatal("old runtime rejected before maintenance", e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	after, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(after.Applied) != len(steps) || len(after.Pending) != 0 || !after.SafetyValid {
		t.Fatal("scheduled retention upgrade", e)
	}
	for n, r := range before.Applied {
		if after.Applied[n] != r {
			t.Fatal("frozen receipt changed", n)
		}
	}
	if e = checkSchemaPlan(ctx, runtime, steps[:7], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old runtime accepted schema eight", e)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	for _, table := range []string{"retention_schedules", "retention_schedule_revisions", "retention_schedule_runs"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		if _, e = owner.Exec(ctx, `ALTER TABLE `+q+` NO FORCE ROW LEVEL SECURITY`); e != nil {
			t.Fatal(e)
		}
		if e = checkSchema(ctx, runtime, true); !errors.Is(e, ErrSchemaIncompatible) {
			t.Fatal("unsafe schedule table admitted", table, e)
		}
		if _, e = owner.Exec(ctx, `ALTER TABLE `+q+` FORCE ROW LEVEL SECURITY`); e != nil {
			t.Fatal(e)
		}
		if table != "retention_schedules" {
			for _, verb := range []string{`DELETE FROM ` + q + ` WHERE false`, `UPDATE ` + q + ` SET tenant=tenant WHERE false`} {
				_, e = runtime.Exec(ctx, verb)
				var pe *pgconn.PgError
				if !errors.As(e, &pe) || pe.Code != "42501" {
					t.Fatal("runtime can rewrite immutable scheduling evidence", table, e)
				}
			}
		}
	}
	if e = checkSchema(ctx, runtime, true); e != nil {
		t.Fatal(e)
	}
	t.Logf("migration eight checksum: %s", after.Applied[7].Checksum)
}
