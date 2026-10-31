//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"testing"

	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func TestIntegrityScheduleMigrationPreservesFiveReceiptsAndGuardsNewTenantTables(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:5]); e != nil {
		t.Fatal(e)
	}
	before, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(before.Applied) != 5 || len(before.Pending) != len(steps)-5 || before.Pending[0] != 6 || !before.SafetyValid {
		t.Fatal(before, e)
	}
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:5], true); e != nil {
		t.Fatal("safe schema-5 runtime rejected", e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	after, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(after.Applied) != len(steps) || !after.SafetyValid || len(after.Pending) != 0 {
		t.Fatal(after, e)
	}
	for n, receipt := range before.Applied {
		if after.Applied[n] != receipt {
			t.Fatal("frozen receipt changed", n)
		}
	}
	if e = checkSchemaPlan(ctx, runtime, steps[:5], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted new scheduler schema", e)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	for _, name := range []string{"integrity_schedules", "integrity_schedule_revisions", "integrity_schedule_runs"} {
		table := pgx.Identifier{"cratectl", name}.Sanitize()
		if _, e = owner.Exec(ctx, `ALTER TABLE `+table+` NO FORCE ROW LEVEL SECURITY`); e != nil {
			t.Fatal(e)
		}
		if e = checkSchema(ctx, runtime, true); !errors.Is(e, ErrSchemaIncompatible) {
			t.Fatal("unsafe schedule table admitted", name, e)
		}
		if _, e = owner.Exec(ctx, `ALTER TABLE `+table+` FORCE ROW LEVEL SECURITY`); e != nil {
			t.Fatal(e)
		}
	}
	if e = checkSchema(ctx, runtime, true); e != nil {
		t.Fatal(e)
	}
	t.Logf("migration six checksum: %s", after.Applied[5].Checksum)
}
