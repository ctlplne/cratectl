//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
)

// This declared schema14 SQL fixture is distinct from the workflow's real
// qualified809e826 historical binary and stock-client maintenance journey.
func TestGoModuleExportSchema14UpgradePreservesReceiptsRowsAndRLS(t *testing.T) {
	d := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	steps := currentMigrations()
	if err := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:14]); err != nil {
		t.Fatal(err)
	}
	beforePlan, err := MigrationPlan(ctx, d.OwnerDSN)
	if err != nil || !reflect.DeepEqual(beforePlan.Pending, []int{15}) || len(beforePlan.Applied) != 14 {
		t.Fatal("prior14 plan", err)
	}
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('cratectl.tenant','schema14-export',true)`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO cratectl.tenants(tenant)VALUES('schema14-export')`,
		`INSERT INTO cratectl.repositories(tenant,name,format,require_review)VALUES('schema14-export','retained','generic',true)`,
		`INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,decision)VALUES('schema14-export','retained','original.bin',repeat('a',64),7,'application/octet-stream','{"original":true}','allowed')`,
		`INSERT INTO cratectl.events(tenant,sequence,payload,previous_hash,hash)VALUES('schema14-export',1,'{"tenant":"schema14-export","sequence":1,"kind":"owned.fixture","data":{}}','','` + crypt.Digest([]byte("\n"+`{"tenant":"schema14-export","sequence":1,"kind":"owned.fixture","data":{}}`)) + `')`,
		`INSERT INTO cratectl.jobs(tenant,sequence,task,kind,queue)VALUES('schema14-export',1,'event','storage.inventory','integrity')`,
		`INSERT INTO cratectl.inventory_entries(tenant,sequence,task,ordinal,area,name_b64,display_name,entry_type,size,modified_ns,file_identity,expected_layout,digest,artifact_references)VALUES('schema14-export',1,'event',1,'cas','b3JpZ2luYWw','original','file',7,1,'owned-file',true,repeat('a',64),1)`,
		`INSERT INTO cratectl.mutations(tenant,actor,key,fingerprint,response,status)VALUES('schema14-export','operator','old-receipt',repeat('b',64),'original-response'::bytea,201)`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal("owned declared prior rows", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot := func(after bool) map[string]string {
		t.Helper()
		out := map[string]string{}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT set_config('cratectl.tenant','schema14-export',true)`); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"repositories", "artifacts", "events", "jobs", "mutations", "inventory_entries"} {
			expr := "to_jsonb(x)"
			if after && name == "inventory_entries" {
				expr += "-'export_references'"
			}
			var raw string
			if err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(`+expr+` ORDER BY `+expr+`),'[]'::jsonb)::text FROM cratectl.`+name+` x`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			out[name] = raw
		}
		return out
	}
	before := snapshot(false)
	if err := Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal(err)
	}
	afterPlan, err := MigrationPlan(ctx, d.OwnerDSN)
	if err != nil || len(afterPlan.Applied) != 15 || !afterPlan.SafetyValid || !reflect.DeepEqual(afterPlan.Applied[:14], beforePlan.Applied) || !reflect.DeepEqual(before, snapshot(true)) {
		t.Fatal("schema15 changed old durable bytes or receipts", err)
	}
	runtime, err := pgx.Connect(ctx, d.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	if err := checkSchemaPlan(ctx, runtime, steps[:14], true); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatal("schema14 runtime admitted15", err)
	}
	if err := checkSchemaPlan(ctx, runtime, steps, true); err != nil {
		t.Fatal("matching15 runtime refused", err)
	}
	for _, name := range []string{"artifact_exports", "artifact_export_items"} {
		var n int
		if err := runtime.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+name).Scan(&n); err != nil || n != 0 {
			t.Fatal("tenantless runtime exposed exports", name, err)
		}
	}
	if err := Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal("schema15 no-op replay", err)
	}
	if _, err := owner.Exec(ctx, `ALTER TABLE cratectl.artifact_exports NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrationPlan(ctx, d.OwnerDSN); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatal("unsafe new export table admitted", err)
	}
	if err := checkSchemaPlan(ctx, runtime, steps, true); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatal("runtime ignored new export FORCE boundary", err)
	}
}
