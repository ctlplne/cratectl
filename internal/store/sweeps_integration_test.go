//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func sweepID(t *testing.T, r Result) string {
	t.Helper()
	var data struct{ Job string }
	if json.Unmarshal(r.Body, &data) != nil || data.Job == "" {
		t.Fatal(string(r.Body))
	}
	return data.Job
}
func TestSweepSnapshotsAllReferencesFencesProgressAndRetainsPasses(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	data := Artifact{Path: "old", Digest: strings.Repeat("a", 64), Size: 3, MediaType: "application/octet-stream"}
	// Existing content deliberately has no publication-time jobs.
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,decision) VALUES($1,'packages','old',$2,3,'application/octet-stream','denied'),($1,'packages','alias',$2,3,'application/octet-stream','unassessed'),($1,'packages','conflicting-size',$2,4,'application/octet-stream','unassessed')`, admin.Tenant, data.Digest); e != nil {
			return e
		}
		if e := CreateRepository(ctx, tx, admin, Repository{Name: "images", Format: "oci"}); e != nil {
			return e
		}
		id := strings.Repeat("x", 43)
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.uploads(tenant,repository,image,id,state) VALUES($1,'images','app',$2,'cancelled')`, admin.Tenant, id); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.upload_parts(tenant,upload_id,offset_bytes,digest,size) VALUES($1,$2,0,$3,5)`, admin.Tenant, id, strings.Repeat("b", 64))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	preview, more, e := db.PreviewSweep(ctx, admin, SweepRequest{}, 1)
	if e != nil || !more || len(preview) != 1 {
		t.Fatal(preview, more, e)
	}
	// Budget rejection must not acknowledge or retain any partial snapshot/job.
	if _, e = db.StartSweep(ctx, admin, "too-small", "small", SweepRequest{}, 2); !errors.Is(e, ErrSweepBudget) {
		t.Fatal("snapshot budget bypassed", e)
	}
	if e = db.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		var count int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.sweep_items`).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			t.Fatal("rejected snapshot retained rows", count)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	first, e := db.StartSweep(ctx, admin, "sweep-start", "same", SweepRequest{}, 3)
	if e != nil {
		t.Fatal(e)
	}
	id := sweepID(t, first)
	replay, e := db.StartSweep(ctx, admin, "sweep-start", "same", SweepRequest{}, 3)
	if e != nil || !replay.Replay || string(replay.Body) != string(first.Body) {
		t.Fatal("idempotency replay changed", e)
	}
	j, e := db.Job(ctx, admin, id)
	if e != nil || j.Handler != "storage.sweep" {
		t.Fatal(j, e)
	}
	p, e := sweepProgress(j.Target)
	if e != nil || p.Targets != 3 || p.ArtifactReferences != 3 || p.UploadParts != 1 {
		t.Fatal("snapshot counts", p, e)
	}
	// Later references do not enter the immutable snapshot, even behind its cursor.
	if e = db.Publish(ctx, admin, "packages", []Artifact{{Path: "later", Digest: strings.Repeat("0", 64), Size: 1, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	// Claim the admitted sweep before the newer publication job.
	old, e := db.ClaimJob(ctx, worker, "integrity", "node-old", time.Minute)
	if e != nil || old.ID() != id {
		t.Fatal(old, e)
	}
	target, empty, e := db.NextSweepItem(ctx, worker, old)
	if e != nil || empty || target.UploadParts != 1 {
		t.Fatal(target, empty, e)
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET lease_until='epoch' WHERE sequence=$1 AND task=$2`, old.Sequence, old.Task)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	replacement, e := db.ClaimJob(ctx, worker, "integrity", "node-new", time.Minute)
	if e != nil || replacement.ID() != id || replacement.Generation <= old.Generation {
		t.Fatal(replacement, e)
	}
	if _, e = db.FinishSweepItem(ctx, worker, old, target, "verified"); !errors.Is(e, ErrJobLeaseLost) {
		t.Fatal("stale owner advanced sweep", e)
	}
	if outcome, e := db.FinishSweepItem(ctx, worker, replacement, target, "verified"); e != nil || outcome != "pending" {
		t.Fatal(outcome, e)
	}
	items, more, e := db.SweepItems(ctx, admin, id, 0, 1)
	if e != nil || !more || items[0].Status != "verified" {
		t.Fatal(items, more, e)
	}
	if _, e = db.ControlJob(ctx, admin, "cancel-sweep", "cancel", id, "cancel", false); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ControlJob(ctx, admin, "resume-sweep", "resume", id, "retry", false); e != nil {
		t.Fatal(e)
	}
	// Other ready integrity work receives a turn before the yielded sweep.
	next, e := db.ClaimJob(ctx, worker, "integrity", "fair-node", time.Minute)
	if e != nil || next.ID() == id {
		t.Fatal("sweep monopolized integrity lane", next, e)
	}
	if _, e = db.FinishIntegrity(ctx, worker, next, "verified"); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 2; n++ {
		claim, e := db.ClaimJob(ctx, worker, "integrity", "sweep-node", time.Minute)
		if e != nil || claim.ID() != id {
			t.Fatal(claim, e)
		}
		target, empty, e := db.NextSweepItem(ctx, worker, claim)
		if e != nil || empty || !target.ReferenceConflict {
			t.Fatal(target, empty, e)
		}
		if _, e = db.FinishSweepItem(ctx, worker, claim, target, "verified"); e != nil {
			t.Fatal(e)
		}
	}
	detail, e := db.Sweep(ctx, admin, id)
	if e != nil || detail["all_targets_assessed"] != true || detail["integrity_clean"] != false || detail["security_approval"] != false {
		t.Fatal(detail, e)
	}
	j, e = db.Job(ctx, admin, id)
	if e != nil {
		t.Fatal(e)
	}
	p, e = sweepProgress(j.Target)
	if e != nil || p.Checked != 3 || p.Verified != 1 || p.Issues != 2 {
		t.Fatal("dishonest counts", p, e)
	}
	observations, more, e := db.JobObservations(ctx, admin, id, 0, 10)
	if e != nil || more || len(observations) != 3 || observations[0].Ordinal != 1 || observations[0].Pass != 1 {
		t.Fatal(observations, more, e)
	}
	if _, e = db.ControlJob(ctx, admin, "recheck-sweep", "recheck", id, "retry", false); e != nil {
		t.Fatal(e)
	}
	j, e = db.Job(ctx, admin, id)
	if e != nil {
		t.Fatal(e)
	}
	p, e = sweepProgress(j.Target)
	if e != nil || p.Pass != 2 || p.Checked != 0 || p.Targets != 3 {
		t.Fatal("completed redrive did not reset pass", p, e)
	}
	items, _, e = db.SweepItems(ctx, admin, id, 0, 10)
	if e != nil || len(items) != 3 {
		t.Fatal(items, e)
	}
	for _, item := range items {
		if item.Status != "pending" {
			t.Fatal("previous pass shown as current", item)
		}
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, _, e = db.SweepItems(ctx, other, id, 0, 10); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant snapshot crossed", e)
	}
}

func TestSweepRunningCancellationDoesNotRecordAnObservation(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	if e := db.Publish(ctx, admin, "packages", []Artifact{{Path: "item", Digest: strings.Repeat("c", 64), Size: 2, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	publication, e := db.ClaimJob(ctx, worker, "integrity", "pub", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.FinishIntegrity(ctx, worker, publication, "verified"); e != nil {
		t.Fatal(e)
	}
	started, e := db.StartSweep(ctx, admin, "start-cancel", "cancel-target", SweepRequest{}, 10)
	if e != nil {
		t.Fatal(e)
	}
	id := sweepID(t, started)
	claim, e := db.ClaimJob(ctx, worker, "integrity", "sweep", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	item, _, e := db.NextSweepItem(ctx, worker, claim)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.ControlJob(ctx, admin, "cancel-running", "cancel-running", id, "cancel", false); e != nil {
		t.Fatal(e)
	}
	if state, e := db.FinishSweepItem(ctx, worker, claim, item, "verified"); e != nil || state != "cancelled" {
		t.Fatal(state, e)
	}
	obs, _, e := db.JobObservations(ctx, admin, id, 0, 10)
	if e != nil || len(obs) != 0 {
		t.Fatal("cancelled observation committed", obs, e)
	}
}

func TestCredentialExpiringDuringBulkMutationRollsBack(t *testing.T) {
	db, ctx, admin, _, _, _ := jobFixture(t)
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), admin.Tenant, "bulk-admin", "admin", token, time.Now().Add(250*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	actor, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Tx(ctx, actor, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET require_review=true WHERE name='packages'`); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `SELECT pg_sleep(0.35)`)
		return e
	})
	if !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("expired bulk mutation committed", e)
	}
	repo, e := db.Repository(context.Background(), admin, "packages")
	if e != nil || repo.RequireReview {
		t.Fatal("expired mutation effects survived", repo, e)
	}
}

func TestSweepSizeConflictsFollowTenantCASAcrossRepositories(t *testing.T) {
	db, ctx, admin, _, _, _ := jobFixture(t)
	digest := strings.Repeat("d", 64)
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if e := CreateRepository(ctx, tx, admin, Repository{Name: "second", Format: "generic"}); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type) VALUES($1,'packages','object',$2,3,'application/octet-stream'),($1,'second','object',$2,3,'application/octet-stream')`, admin.Tenant, digest)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	items, _, e := db.PreviewSweep(ctx, admin, SweepRequest{}, 10)
	if e != nil || len(items) != 2 {
		t.Fatal(items, e)
	}
	for _, item := range items {
		if item.ReferenceConflict {
			t.Fatal("same digest and size in two repositories is not a conflict")
		}
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET size=4 WHERE repository='second'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	items, _, e = db.PreviewSweep(ctx, admin, SweepRequest{}, 10)
	if e != nil {
		t.Fatal(e)
	}
	for _, item := range items {
		if !item.ReferenceConflict {
			t.Fatal("cross-repository CAS size conflict hidden", item)
		}
	}
}
