//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func TestLifecycleMigrationPreservesV2ReceiptsAndGuardsRLS(t *testing.T) {
	d := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:2]); e != nil {
		t.Fatal(e)
	}
	plan, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || plan.DatabaseState != "pending" || len(plan.Pending) != 1 || plan.Pending[0] != 3 || !plan.SafetyValid {
		t.Fatal(plan, e)
	}
	old := append([]SchemaReceipt(nil), plan.Applied...)
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:2], true); e != nil {
		t.Fatal("valid v2 runtime", e)
	}
	if e = checkSchemaPlan(ctx, runtime, steps, true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("new runtime admitted v2", e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	plan, e = MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || plan.DatabaseState != "current" || len(plan.Applied) != 3 || !plan.SafetyValid {
		t.Fatal(plan, e)
	}
	for n := range old {
		if old[n] != plan.Applied[n] {
			t.Fatal("changed applied receipt")
		}
	}
	if e = checkSchemaPlan(ctx, runtime, steps[:2], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted v3", e)
	}
	if e = checkSchemaPlan(ctx, runtime, steps, true); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"artifact_lifecycle", "repository_lifecycle"} {
		var count int
		if e = runtime.QueryRow(ctx, "SELECT count(*) FROM cratectl."+table).Scan(&count); e != nil || count != 0 {
			t.Fatal(table, count, e)
		}
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `ALTER TABLE cratectl.artifact_lifecycle NO FORCE ROW LEVEL SECURITY`); e != nil {
		t.Fatal(e)
	}
	if _, e = MigrationPlan(ctx, d.OwnerDSN); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("unsafe lifecycle table accepted", e)
	}
	if e = checkSchemaPlan(ctx, runtime, steps, true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("unsafe lifecycle runtime accepted", e)
	}
}
