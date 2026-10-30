//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"ctlplne.dev/cratectl/internal/testdb"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
)

func TestRepairMigrationPreservesFourReceiptsAndRejectsOldWorkers(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:4]); e != nil {
		t.Fatal(e)
	}
	before, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(before.Applied) != 4 || len(before.Pending) != 1 || before.Pending[0] != 5 || !before.SafetyValid {
		t.Fatal(before, e)
	}
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:4], true); e != nil {
		t.Fatal("valid old runtime rejected before upgrade", e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	after, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || after.DatabaseState != "current" || len(after.Applied) != 5 || !after.SafetyValid {
		t.Fatal(after, e)
	}
	for n, receipt := range before.Applied {
		if after.Applied[n] != receipt {
			t.Fatal("frozen prior migration changed", n)
		}
	}
	if e = checkSchemaPlan(ctx, runtime, steps[:4], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old worker admitted repair database", e)
	}
	t.Logf("migration five checksum: %s", after.Applied[4].Checksum)
}
