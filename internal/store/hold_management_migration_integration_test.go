//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func TestHoldManagementUpgradePreservesEightReceiptsAndJournal(t *testing.T) {
	testHoldUpgradePreservesReceiptsAndJournal(t, 8)
}
func TestHoldCasesUpgradePreservesNineReceiptsAndJournal(t *testing.T) {
	testHoldUpgradePreservesReceiptsAndJournal(t, 9)
}
func testHoldUpgradePreservesReceiptsAndJournal(t *testing.T, baseline int) {
	t.Helper()
	d := testdb.New(t)
	ctx := context.Background()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:baseline]); e != nil {
		t.Fatal(e)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal("owned migration connection")
	}
	defer owner.Close(ctx)
	i := Identity{Tenant: "hold-upgrade", Actor: "operator", Role: "admin"}
	digest := strings.Repeat("a", 64)
	path := "app/manifests/sha256:" + digest
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := ArtifactState{Repository: "held", Path: path, Digest: digest, Held: true, Revision: 1, HoldReason: "Existing retained hold", Reason: "Existing retained hold", Actor: i.Actor, ChangedAt: &now, ChangeSequence: 1}
	tx, e := owner.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('cratectl.tenant',$1,true)", i.Tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO cratectl.tenants(tenant) VALUES($1)", i.Tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO cratectl.repositories(tenant,name,format) VALUES($1,'held','oci')", i.Tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type) VALUES($1,'held',$2,$3,1,'application/vnd.oci.image.index.v1+json')", i.Tenant, path, digest); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,revision,hold_reason,reason,actor,changed_at,change_sequence) VALUES($1,'held',$2,$3,1,$4,$4,$5,$6,1)", i.Tenant, path, digest, snapshot.Reason, i.Actor, now); e != nil {
		t.Fatal(e)
	}
	if e = appendEventIntent(ctx, tx, i, "artifact.lifecycle.changed", ArtifactStatePreview{Current: snapshot, Action: "hold", RetainedBytes: true}, false); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	// This is a declared prior-schema SQL fixture; stock old-binary upgrade is a
	// separate native journey, not inferred from these rows.
	var payloadBefore, hashBefore string
	if e = owner.QueryRow(ctx, "SELECT payload,hash FROM cratectl.events WHERE tenant=$1 AND sequence=1", i.Tenant).Scan(&payloadBefore, &hashBefore); e != nil {
		t.Fatal(e)
	}
	before, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(before.Applied) != baseline || len(before.Pending) != len(steps)-baseline || before.Pending[0] != baseline+1 {
		t.Fatal("prior-schema baseline", before, e)
	}
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal("owned runtime connection")
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:baseline], true); e != nil {
		t.Fatal("old runtime admission before maintenance", e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	after, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(after.Applied) != len(steps) || !after.SafetyValid || len(after.Pending) != 0 {
		t.Fatal("hold upgrade", after, e)
	}
	for n, r := range before.Applied {
		if after.Applied[n] != r {
			t.Fatal("applied receipt changed", n)
		}
	}
	var payloadAfter, hashAfter string
	if e = owner.QueryRow(ctx, "SELECT payload,hash FROM cratectl.events WHERE tenant=$1 AND sequence=1", i.Tenant).Scan(&payloadAfter, &hashAfter); e != nil || payloadAfter != payloadBefore || hashAfter != hashBefore {
		t.Fatal("upgrade rewrote journal bytes", e)
	}
	if e = checkSchemaPlan(ctx, runtime, steps[:baseline], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted newer schema", e)
	}
	db, e := Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	held, _, _, e := db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 10}, State: "all"})
	if e != nil || len(held) != 1 || held[0].Status != "active" || held[0].Revision != 1 {
		t.Fatal("existing hold disappeared", held, e)
	}
	history, _, e := db.HoldHistory(ctx, i, "held", path, ListRequest{Limit: 10})
	if e != nil || len(history) != 1 || history[0].EventHash != hashBefore || history[0].State.HoldReason != snapshot.HoldReason {
		t.Fatal("original receipt unavailable", history, e)
	}
	var count int
	if e = runtime.QueryRow(ctx, "SELECT count(*) FROM cratectl.artifact_lifecycle").Scan(&count); e != nil || count != 0 {
		t.Fatal("runtime hold table bypassed tenant RLS", count, e)
	}
	if e = runtime.QueryRow(ctx, "SELECT count(*) FROM cratectl.events").Scan(&count); e != nil || count != 0 {
		t.Fatal("runtime journal bypassed tenant RLS", count, e)
	}
	if e = owner.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE schemaname='cratectl' AND indexname IN ('artifact_lifecycle_hold_page_idx','artifact_lifecycle_hold_history_idx')").Scan(&count); e != nil || count != 2 {
		t.Fatal("bounded lookup indexes absent", count, e)
	}
}
