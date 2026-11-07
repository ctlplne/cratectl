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

// These declared old-schema SQL fixtures are distinct from the workflow's
// qualified historical daemons, real export manifests and stock-client journey.
func TestGoModuleExportSchema14UpgradePreservesReceiptsRowsAndRLS(t *testing.T) {
	testGoExportOldSchemaUpgrade(t, 14)
}

func TestGoModuleExportSchema15UpgradePreservesRowsAndRequiresExactExpiryIndex(t *testing.T) {
	testGoExportOldSchemaUpgrade(t, 15)
}

func TestGoModuleExportSetSchema16UpgradePreservesAllOldRowsReceiptsAndRLS(t *testing.T) {
	testGoExportOldSchemaUpgrade(t, 16)
}

func testGoExportOldSchemaUpgrade(t *testing.T, baseline int) {
	t.Helper()
	d := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	steps := currentMigrations()
	if err := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:baseline]); err != nil {
		t.Fatal(err)
	}
	beforePlan, err := MigrationPlan(ctx, d.OwnerDSN)
	pending := []int{}
	for version := baseline + 1; version <= len(steps); version++ {
		pending = append(pending, version)
	}
	if err != nil || !reflect.DeepEqual(beforePlan.Pending, pending) || len(beforePlan.Applied) != baseline {
		t.Fatal("prior schema plan", err)
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
	if baseline >= 15 {
		for _, sql := range []string{
			`INSERT INTO cratectl.artifact_exports(tenant,id,repository,source_revision,module,version,actor,manifest_digest,manifest_size,state,generation,created_sequence,change_sequence,expires_at,max_expires_at)VALUES('schema14-export',repeat('c',64),'retained',0,'go.cratectl.invalid/Owned/fixture','v1.0.0','operator',repeat('b',64),17,'acknowledged',2,1,1,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '23 hours')`,
			`INSERT INTO cratectl.artifact_export_items(tenant,export_id,ordinal,path,digest,size)VALUES('schema14-export',repeat('c',64),0,'original.bin',repeat('a',64),7)`,
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				t.Fatal("owned declared15 export rows", err)
			}
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
		tables := []string{"tenants", "repositories", "artifacts", "events", "jobs", "mutations", "inventory_entries"}
		if baseline >= 15 {
			tables = schemaTablesV15
		}
		for _, name := range tables {
			expr := "to_jsonb(x)"
			if after && baseline == 14 && name == "inventory_entries" {
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
	if err != nil || len(afterPlan.Applied) != 17 || !afterPlan.SafetyValid || !reflect.DeepEqual(afterPlan.Applied[:baseline], beforePlan.Applied) || !reflect.DeepEqual(before, snapshot(true)) {
		t.Fatal("schema17 changed old durable bytes or receipts", err)
	}
	runtime, err := pgx.Connect(ctx, d.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	if err := checkSchemaPlan(ctx, runtime, steps[:baseline], true); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted17", err)
	}
	if err := checkSchemaPlan(ctx, runtime, steps, true); err != nil {
		t.Fatal("matching17 runtime refused", err)
	}
	for _, name := range []string{"artifact_exports", "artifact_export_items", "artifact_export_sets", "artifact_export_set_roots", "artifact_export_set_items"} {
		var n int
		if err := runtime.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+name).Scan(&n); err != nil || n != 0 {
			t.Fatal("tenantless runtime exposed exports", name, err)
		}
	}
	if err := Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal("schema16 no-op replay", err)
	}
	if baseline >= 15 {
		for name, definition := range map[string]string{
			"missing":              "",
			"wrong order":          `CREATE INDEX artifact_exports_due ON cratectl.artifact_exports(tenant,id,expires_at) WHERE state IN ('open','acknowledged')`,
			"missing acknowledged": `CREATE INDEX artifact_exports_due ON cratectl.artifact_exports(tenant,expires_at,id) WHERE state='open'`,
			"descending":           `CREATE INDEX artifact_exports_due ON cratectl.artifact_exports(tenant,expires_at DESC,id) WHERE state IN ('open','acknowledged')`,
			"included payload":     `CREATE INDEX artifact_exports_due ON cratectl.artifact_exports(tenant,expires_at,id) INCLUDE(state) WHERE state IN ('open','acknowledged')`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, `DROP INDEX cratectl.artifact_exports_due`); err != nil {
					t.Fatal(err)
				}
				if definition != "" {
					if _, err := owner.Exec(ctx, definition); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := MigrationPlan(ctx, d.OwnerDSN); !errors.Is(err, ErrSchemaIncompatible) {
					t.Fatal("migrator admitted altered expiry index", err)
				}
				if err := checkSchemaPlan(ctx, runtime, steps, true); !errors.Is(err, ErrSchemaIncompatible) {
					t.Fatal("runtime admitted altered expiry index", err)
				}
				if definition != "" {
					if _, err := owner.Exec(ctx, `DROP INDEX cratectl.artifact_exports_due`); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := owner.Exec(ctx, goExportExpirySchema); err != nil {
					t.Fatal(err)
				}
			})
		}
		if plan, err := MigrationPlan(ctx, d.OwnerDSN); err != nil || !plan.SafetyValid || !reflect.DeepEqual(plan.Applied, afterPlan.Applied) || !reflect.DeepEqual(before, snapshot(true)) {
			t.Fatal("index repair changed original rows or receipts", err)
		}
		t.Logf("declared schema15 preserved %d tenant tables and15 receipts; exact schema16 index required", len(schemaTablesV15))
	}

	if baseline == 16 {
		for _, statement := range []string{
			`UPDATE cratectl.artifact_export_sets SET manifest_digest=repeat('e',64)`,
			`UPDATE cratectl.artifact_export_set_roots SET module='go.cratectl.invalid/changed'`,
			`UPDATE cratectl.artifact_export_set_items SET digest=repeat('e',64)`,
			`DELETE FROM cratectl.artifact_export_sets`,
			`DELETE FROM cratectl.artifact_export_set_roots`,
			`DELETE FROM cratectl.artifact_export_set_items`,
		} {
			if _, err := runtime.Exec(ctx, statement); err == nil {
				t.Fatal("runtime can rewrite immutable common export identity", statement)
			}
		}
		if _, err := owner.Exec(ctx, `DROP INDEX cratectl.artifact_export_sets_due`); err != nil {
			t.Fatal(err)
		}
		if _, err := MigrationPlan(ctx, d.OwnerDSN); !errors.Is(err, ErrSchemaIncompatible) {
			t.Fatal("schema17 missing expiry index admitted", err)
		}
		if err := checkSchemaPlan(ctx, runtime, steps, true); !errors.Is(err, ErrSchemaIncompatible) {
			t.Fatal("runtime ignored missing common expiry index", err)
		}
		if _, err := owner.Exec(ctx, `CREATE INDEX artifact_export_sets_due ON cratectl.artifact_export_sets(tenant,expires_at,id) WHERE state IN ('open','acknowledged')`); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"artifact_export_sets", "artifact_export_set_roots", "artifact_export_set_items"} {
			if _, err := owner.Exec(ctx, `ALTER TABLE cratectl.`+name+` NO FORCE ROW LEVEL SECURITY`); err != nil {
				t.Fatal(err)
			}
			if err := checkSchemaPlan(ctx, runtime, steps, true); !errors.Is(err, ErrSchemaIncompatible) {
				t.Fatal("runtime ignored common table FORCE boundary", name, err)
			}
			if _, err := owner.Exec(ctx, `ALTER TABLE cratectl.`+name+` FORCE ROW LEVEL SECURITY`); err != nil {
				t.Fatal(err)
			}
		}
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
