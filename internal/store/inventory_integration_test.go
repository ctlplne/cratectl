//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func inventoryID(t *testing.T, r Result) string {
	t.Helper()
	var data struct{ Job string }
	if json.Unmarshal(r.Body, &data) != nil || data.Job == "" {
		t.Fatal(string(r.Body))
	}
	return data.Job
}
func inventoryFixture(t *testing.T) (*Store, context.Context, Identity, WorkerIdentity, *blob.Local, string) {
	t.Helper()
	db, ctx, i, w, _, _ := jobFixture(t)
	root := t.TempDir()
	objects, e := blob.New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	return db, ctx, i, w, objects, root
}
func startTestInventory(t *testing.T, db *Store, ctx context.Context, i Identity, objects *blob.Local, limits InventoryLimits, page int) string {
	t.Helper()
	root, e := objects.InventoryRoot(i.Tenant)
	if e != nil {
		t.Fatal(e)
	}
	token, _ := crypt.Token()
	r, e := db.StartInventory(ctx, i, token, token, root, InventoryRequest{PageSize: page}, limits, 100)
	if e != nil {
		t.Fatal(e)
	}
	return inventoryID(t, r)
}
func finishInventoryStep(t *testing.T, db *Store, ctx context.Context, w WorkerIdentity, objects *blob.Local, j Job) (string, error) {
	t.Helper()
	step, e := db.PrepareInventoryStep(ctx, w, j)
	if e != nil {
		return "", e
	}
	switch step.Kind {
	case "page":
		page, e := objects.ListInventoryPage(ctx, w.Tenant, step.Progress.RootIdentity, step.Area, step.Bucket, step.Progress.AfterName, step.Progress.PageSize, step.Progress.DirectoryEntries)
		if e != nil {
			return "", e
		}
		return db.FinishInventoryPage(ctx, w, j, page)
	case "hash":
		status, e := objects.CheckInventoryObject(ctx, w.Tenant, step.Progress.RootIdentity, step.Entry, 1<<20, 0)
		if e != nil {
			return "", e
		}
		return db.FinishInventoryHash(ctx, w, j, step, status)
	case "reference":
		status, e := objects.CheckStored(ctx, w.Tenant, step.Reference.Digest, step.Reference.Size, 1<<20, 0)
		if e != nil {
			return "", e
		}
		return db.FinishInventoryReference(ctx, w, j, step.Reference, status)
	default:
		return db.FinishInventoryTransition(ctx, w, j, step.Kind)
	}
}
func driveTestInventory(t *testing.T, db *Store, ctx context.Context, w WorkerIdentity, objects *blob.Local, id string) {
	t.Helper()
	for n := 0; n < 100; n++ {
		j, e := db.ClaimJob(ctx, w, "integrity", "inventory-test", time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if j.ID() != id {
			if j.Kind != "artifact.integrity" {
				t.Fatal("unexpected work", j)
			}
			if _, e = db.FinishIntegrity(ctx, w, j, "verified"); e != nil {
				t.Fatal(e)
			}
			continue
		}
		state, e := finishInventoryStep(t, db, ctx, w, objects, j)
		if e != nil {
			t.Fatal(e)
		}
		if state == "succeeded" {
			return
		}
	}
	t.Fatal("inventory did not finish")
}
func TestInventoryDurableWalkFencesCurrentReferencesAndPasses(t *testing.T) {
	db, ctx, i, w, objects, root := inventoryFixture(t)
	original, e := objects.Put(ctx, i.Tenant, strings.NewReader("referenced bytes"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	orphan, e := objects.Put(ctx, i.Tenant, strings.NewReader("retained orphan bytes"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Publish(ctx, i, "packages", []Artifact{{Path: "original", Digest: original.Digest, Size: original.Size, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, Repository{Name: "images", Format: "oci"}) }); e != nil {
		t.Fatal(e)
	}
	upload := createTestUpload(t, db, ctx, i, "images")
	if _, e = objects.AppendUpload(ctx, i.Tenant, upload, 0, strings.NewReader("acknowledged-tail")); e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET offset_bytes=5 WHERE id=$1`, upload)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, i.Tenant, "staged", "upload-owned-retained"), []byte("staged"), 0600); e != nil {
		t.Fatal(e)
	}
	id := startTestInventory(t, db, ctx, i, objects, InventoryLimits{MaxEntries: 100, DirectoryEntries: 100}, 1)
	publication, e := db.ClaimJob(ctx, w, "integrity", "publication", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.FinishIntegrity(ctx, w, publication, "verified"); e != nil {
		t.Fatal(e)
	}
	old, e := db.ClaimJob(ctx, w, "integrity", "old", time.Minute)
	if e != nil || old.ID() != id {
		t.Fatal(old, e)
	}
	spec, e := db.PrepareInventoryStep(ctx, w, old)
	if e != nil {
		t.Fatal(e)
	}
	page, e := objects.ListInventoryPage(ctx, i.Tenant, spec.Progress.RootIdentity, spec.Area, spec.Bucket, spec.Progress.AfterName, 1, 100)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET lease_until='epoch' WHERE sequence=$1 AND task=$2`, old.Sequence, old.Task)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	newer, e := db.ClaimJob(ctx, w, "integrity", "new", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.FinishInventoryPage(ctx, w, old, page); !errors.Is(e, ErrJobLeaseLost) {
		t.Fatal("stale page advanced cursor", e)
	}
	if _, e = db.FinishInventoryPage(ctx, w, newer, page); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ControlJob(ctx, i, "cancel-inventory", "cancel", id, "cancel", false); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ControlJob(ctx, i, "resume-inventory", "resume", id, "retry", false); e != nil {
		t.Fatal(e)
	}
	driveTestInventory(t, db, ctx, w, objects, id)
	detail, e := db.Inventory(ctx, i, id)
	if e != nil || detail["safe_to_delete"] != false || detail["security_approval"] != false || detail["supported_layout_accounted"] != true || detail["cas_integrity_clean"] != true || detail["unverified_temporary_and_legacy_files"] != int64(2) {
		t.Fatal(detail, e)
	}
	j, e := db.Job(ctx, i, id)
	if e != nil {
		t.Fatal(e)
	}
	p, e := inventoryProgress(j.Target)
	if e != nil || p.CASFiles != 2 || p.CASChecked != 2 || p.ReferenceSnapshot.Targets != 1 || p.UnreferencedCASAtWalk != 1 {
		t.Fatal(p, e)
	}
	if e = db.Publish(ctx, i, "packages", []Artifact{{Path: "formerly-unreferenced", Digest: orphan.Digest, Size: orphan.Size, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	items, more, e := db.InventoryItems(ctx, i, id, "cas", 0, 100)
	if e != nil || more || len(items) != 2 {
		t.Fatal(items, more, e)
	}
	for _, item := range items {
		if item.Digest == orphan.Digest && (item.ArtifactReferencesAtWalk != 0 || item.CurrentArtifactReferences != 1) {
			t.Fatal("stale reference count presented as current", item)
		}
	}
	legacy, _, e := db.InventoryItems(ctx, i, id, "uploads", 0, 100)
	if e != nil || len(legacy) != 1 || legacy[0].AcknowledgedBytesAtWalk != 5 || legacy[0].Status != "legacy_retained" {
		t.Fatal(legacy, e)
	}
	if _, e = db.ControlJob(ctx, i, "redrive-inventory", "again", id, "retry", false); e != nil {
		t.Fatal(e)
	}
	driveTestInventory(t, db, ctx, w, objects, id)
	j, e = db.Job(ctx, i, id)
	if e != nil {
		t.Fatal(e)
	}
	again, e := inventoryProgress(j.Target)
	if e != nil || again.Pass != 2 || again.Entries != p.Entries || again.ReferenceSnapshot.Targets != 1 || again.CASChecked != 2 {
		t.Fatal(again, e)
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, _, e = db.InventoryItems(ctx, other, id, "", 0, 100); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant inventory", e)
	}
}

func TestInventoryMissingReferencesCorruptOrphansAndUnknownLayout(t *testing.T) {
	db, ctx, i, w, objects, root := inventoryFixture(t)
	original, e := objects.Put(ctx, i.Tenant, strings.NewReader("missing reference"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Publish(ctx, i, "packages", []Artifact{{Path: "missing", Digest: original.Digest, Size: original.Size, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(root, i.Tenant, "sha256", original.Digest[:2], original.Digest), filepath.Join(root, "saved-original")); e != nil {
		t.Fatal(e)
	}
	orphan, e := objects.Put(ctx, i.Tenant, strings.NewReader("corrupt object"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, i.Tenant, "sha256", orphan.Digest[:2], orphan.Digest), []byte("corrupt bytes!"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, i.Tenant, "unexpected-directory"), 0700); e != nil {
		t.Fatal(e)
	}
	id := startTestInventory(t, db, ctx, i, objects, InventoryLimits{MaxEntries: 100, DirectoryEntries: 100}, 2)
	driveTestInventory(t, db, ctx, w, objects, id)
	detail, e := db.Inventory(ctx, i, id)
	if e != nil || detail["supported_layout_accounted"] != false || detail["cas_integrity_clean"] != false || detail["reference_snapshot_clean"] != false {
		t.Fatal(detail, e)
	}
	refs, _, e := db.InventoryReferences(ctx, i, id, 0, 100)
	if e != nil || len(refs) != 1 || refs[0].Status != "missing" {
		t.Fatal(refs, e)
	}
	items, _, e := db.InventoryItems(ctx, i, id, "cas", 0, 100)
	if e != nil || len(items) != 1 || items[0].Status != "corrupt" {
		t.Fatal(items, e)
	}
}

func TestInventoryTotalBudgetNeverCommitsAnOversizedPage(t *testing.T) {
	db, ctx, i, w, objects, _ := inventoryFixture(t)
	if _, e := objects.Put(ctx, i.Tenant, strings.NewReader("bytes"), "", -1); e != nil {
		t.Fatal(e)
	}
	id := startTestInventory(t, db, ctx, i, objects, InventoryLimits{MaxEntries: 1, DirectoryEntries: 100}, 100)
	j, e := db.ClaimJob(ctx, w, "integrity", "budget", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = finishInventoryStep(t, db, ctx, w, objects, j); !errors.Is(e, ErrInventoryEntries) {
		t.Fatal("oversized page accepted", e)
	}
	items, _, e := db.InventoryItems(ctx, i, id, "", 0, 100)
	if e != nil || len(items) != 0 {
		t.Fatal("partial page survived rollback", items, e)
	}
	if _, e = db.FailJob(ctx, w, j, "inventory_budget", true); e != nil {
		t.Fatal(e)
	}
	detail, e := db.Inventory(ctx, i, id)
	if e != nil || detail["enumeration_finished"] != false || detail["supported_layout_accounted"] != false {
		t.Fatal(detail, e)
	}
}

func TestWorkerCredentialExpiringDuringMetadataBatchRollsBack(t *testing.T) {
	db, ctx, i, _, _, _ := jobFixture(t)
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), i.Tenant, "short-worker", "worker", token, time.Now().Add(250*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	worker, e := db.AuthenticateWorker(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	e = db.workerTx(ctx, worker, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_sleep(0.35)`); e != nil {
			return e
		}
		return appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: worker.Actor, Role: "worker"}, "inventory.fixture.expiry", map[string]string{"fixture": "owned"}, false)
	})
	if !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("expired worker callback committed", e)
	}
	if e = db.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var n int
		e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='inventory.fixture.expiry'`).Scan(&n)
		if e == nil && n != 0 {
			t.Fatal("expired worker effect survived", n)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestInventoryUnknownDirectoryCannotProduceCleanCASVerdict(t *testing.T) {
	db, ctx, i, w, objects, root := inventoryFixture(t)
	if e := os.MkdirAll(filepath.Join(root, i.Tenant, "unknown", "retained-children"), 0700); e != nil {
		t.Fatal(e)
	}
	id := startTestInventory(t, db, ctx, i, objects, InventoryLimits{MaxEntries: 100, DirectoryEntries: 100}, 10)
	driveTestInventory(t, db, ctx, w, objects, id)
	detail, e := db.Inventory(ctx, i, id)
	if e != nil || detail["supported_layout_accounted"] != false || detail["all_cas_files_assessed"] != false || detail["cas_integrity_clean"] != false {
		t.Fatal("unknown children became a clean receipt", detail, e)
	}
}
