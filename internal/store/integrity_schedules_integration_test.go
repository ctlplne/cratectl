//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func scheduleInput() ScheduleRequest {
	return ScheduleRequest{ScheduleSettings: ScheduleSettings{Repository: "packages", IntervalSeconds: 60, SampleSize: 2, Enabled: true, Reason: "Owned recurring integrity regression"}, RunImmediately: true}
}
func configureSchedule(t *testing.T, db *Store, ctx context.Context, i Identity, name, key string, r ScheduleRequest) IntegritySchedule {
	t.Helper()
	v, e := db.SetIntegritySchedule(ctx, i, name, key, key, r, 100)
	if e != nil {
		t.Fatal(e)
	}
	var out IntegritySchedule
	if json.Unmarshal(v.Body, &out) != nil {
		t.Fatal(string(v.Body))
	}
	return out
}
func dueSchedule(t *testing.T, db *Store, ctx context.Context, i Identity, name string, ago time.Duration) {
	t.Helper()
	e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.integrity_schedules SET next_due_at=clock_timestamp()-$2*interval '1 second',retry_at='epoch' WHERE name=$1`, name, int64(ago/time.Second))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}
func finishScheduleSample(t *testing.T, db *Store, ctx context.Context, i WorkerIdentity, id string, corrupt bool) {
	t.Helper()
	for n := 0; n < 10; n++ {
		j, e := db.ClaimJob(ctx, i, "integrity", "sample-test", time.Minute)
		if e != nil || j.ID() != id {
			t.Fatal("claim sample", j, e)
		}
		item, empty, e := db.NextSweepItem(ctx, i, j)
		if e != nil {
			t.Fatal(e)
		}
		status := "verified"
		if empty {
			status = ""
		}
		if corrupt && n == 0 && !empty {
			status = "corrupt"
		}
		state, e := db.FinishSweepItem(ctx, i, j, item, status)
		if e != nil {
			t.Fatal(e)
		}
		if state == "succeeded" {
			return
		}
	}
	t.Fatal("sample did not finish")
}
func seedScheduleBindings(t *testing.T, db *Store, ctx context.Context, i Identity) {
	t.Helper()
	e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		for n, c := range []string{"a", "b", "c", "d", "e"} {
			if _, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,decision)VALUES($1,'packages',$2,$3,3,'application/octet-stream',$4)`, i.Tenant, fmt.Sprintf("file-%d", n), strings.Repeat(c, 64), map[bool]string{true: "denied", false: "unassessed"}[n == 0]); e != nil {
				return e
			}
		}
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,decision)VALUES($1,'packages','alias',$2,3,'application/octet-stream','unassessed')`, i.Tenant, strings.Repeat("a", 64))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestIntegrityScheduleRotatesImmutableSamplesAndDoesNotOverlap(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	seedScheduleBindings(t, db, ctx, admin)
	input := scheduleInput()
	preview := input
	preview.DryRun = true
	if _, e := db.SetIntegritySchedule(ctx, admin, "daily", "", "", preview, 100); e != nil {
		t.Fatal(e)
	}
	if _, e := db.IntegritySchedule(ctx, admin, "daily"); !errors.Is(e, ErrNotFound) {
		t.Fatal("preview created schedule", e)
	}
	first := configureSchedule(t, db, ctx, admin, "daily", "schedule-create", input)
	if first.Revision != 1 || !first.Cursor.valid() {
		t.Fatal(first)
	}
	replay, e := db.SetIntegritySchedule(ctx, admin, "daily", "schedule-create", "schedule-create", input, 100)
	if e != nil || !replay.Replay {
		t.Fatal("configuration replay", e)
	}
	if _, e = db.SetIntegritySchedule(ctx, admin, "daily", "stale-create", "other", input, 100); !errors.Is(e, ErrScheduleRevision) {
		t.Fatal("CAS overwrite", e)
	}
	var admitted []string
	for cycle := 0; cycle < 3; cycle++ {
		if cycle > 0 {
			dueSchedule(t, db, ctx, admin, "daily", 185*time.Second)
		}
		out, e := db.DispatchIntegritySchedule(ctx, worker)
		if e != nil || out.State != "admitted" {
			t.Fatal(out, e)
		}
		admitted = append(admitted, out.Job)
		items, more, e := db.SweepItems(ctx, admin, out.Job, 0, 10)
		if e != nil || more || len(items) != 2 {
			t.Fatal(items, e)
		}
		want := [][]string{{"a", "b"}, {"c", "d"}, {"e", "a"}}[cycle]
		for n, c := range want {
			if items[n].Digest != strings.Repeat(c, 64) {
				t.Fatal("rotation skipped or reordered", cycle, items)
			}
		}
		if cycle == 0 {
			if items[0].ArtifactReferences != 2 {
				t.Fatal("aliases inflated targets", items[0])
			}
			dueSchedule(t, db, ctx, admin, "daily", 0)
			before, e := db.IntegritySchedule(ctx, admin, "daily")
			if e != nil {
				t.Fatal(e)
			}
			deferred, e := db.DispatchIntegritySchedule(ctx, worker)
			if e != nil || deferred.State != "previous_run_active" {
				t.Fatal("overlap admitted", deferred, e)
			}
			after, e := db.IntegritySchedule(ctx, admin, "daily")
			if e != nil || after.Cursor != before.Cursor || !after.NextDueAt.Equal(before.NextDueAt) {
				t.Fatal("deferral consumed slot or cursor", after, e)
			}
			// A changed live reference does not rewrite the captured first sample.
			if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET digest=$1 WHERE path='alias'`, strings.Repeat("e", 64))
				return e
			}); e != nil {
				t.Fatal(e)
			}
			original, _, e := db.SweepItems(ctx, admin, out.Job, 0, 10)
			if e != nil || original[0].ArtifactReferences != 2 {
				t.Fatal("captured set changed", original, e)
			}
		}
		finishScheduleSample(t, db, ctx, worker, out.Job, cycle == 0)
	}
	runs, more, e := db.IntegrityScheduleRuns(ctx, admin, "daily", 0, 2)
	if e != nil || !more || len(runs) != 2 || runs[0].SampleClean || !runs[0].SampleAssessed || runs[1].CoalescedIntervals != 3 {
		t.Fatal("dishonest or lost findings", runs, more, e)
	}
	seq, _, e := ParseJobID(runs[1].Job)
	if e != nil {
		t.Fatal(e)
	}
	last, more, e := db.IntegrityScheduleRuns(ctx, admin, "daily", seq, 2)
	if e != nil || more || len(last) != 1 || !last[0].Wrapped || !last[0].SampleClean || last[0].AllTenantContentAssessed || last[0].SecurityApproval {
		t.Fatal(last, e)
	}
	job, e := db.Job(ctx, admin, admitted[0])
	if e != nil {
		t.Fatal(e)
	}
	p, e := sweepProgress(job.Target)
	if e != nil || p.Issues != 1 {
		t.Fatal("later clean sample erased earlier finding", p, e)
	}
	current, e := db.IntegritySchedule(ctx, admin, "daily")
	if e != nil {
		t.Fatal(e)
	}
	input.ExpectedRevision = current.Revision
	input.Enabled = false
	input.RunImmediately = false
	configureSchedule(t, db, ctx, admin, "daily", "pause-schedule", input)
	dueSchedule(t, db, ctx, admin, "daily", time.Minute)
	if _, e = db.DispatchIntegritySchedule(ctx, worker); !errors.Is(e, ErrNotFound) {
		t.Fatal("paused schedule ran", e)
	}
}
func TestIntegrityScheduleConcurrentAdmissionAndQueueDeferral(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	seedScheduleBindings(t, db, ctx, admin)
	configureSchedule(t, db, ctx, admin, "sample", "concurrent-create", scheduleInput())
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := []ScheduleDispatch{}
	failures := []error{}
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := db.DispatchIntegritySchedule(ctx, worker)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				admitted = append(admitted, out)
			} else if !errors.Is(e, ErrNotFound) {
				failures = append(failures, e)
			}
		}()
	}
	wg.Wait()
	if len(failures) != 0 || len(admitted) != 1 || admitted[0].State != "admitted" {
		t.Fatal("replicas admitted duplicate slots", admitted, failures)
	}
	finishScheduleSample(t, db, ctx, worker, admitted[0].Job, false)
	jobPolicy(t, db, ctx, admin, 1, 1, 2)
	if e := db.Publish(ctx, admin, "packages", []Artifact{{Path: "queue-pressure", Digest: strings.Repeat("f", 64), Size: 1, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	dueSchedule(t, db, ctx, admin, "sample", time.Minute)
	before, e := db.IntegritySchedule(ctx, admin, "sample")
	if e != nil {
		t.Fatal(e)
	}
	out, e := db.DispatchIntegritySchedule(ctx, worker)
	if e != nil || out.State != "integrity_queue_full" {
		t.Fatal("queue capacity bypass", out, e)
	}
	after, e := db.IntegritySchedule(ctx, admin, "sample")
	if e != nil || after.Cursor != before.Cursor || !after.NextDueAt.Equal(before.NextDueAt) || !after.RetryAt.After(before.RetryAt) {
		t.Fatal("deferral lost schedule intent", after, e)
	}
	j, e := db.ClaimJob(ctx, worker, "integrity", "pressure-drain", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.FinishIntegrity(ctx, worker, j, "verified"); e != nil {
		t.Fatal(e)
	}
	dueSchedule(t, db, ctx, admin, "sample", time.Minute)
	out, e = db.DispatchIntegritySchedule(ctx, worker)
	if e != nil || out.State != "admitted" {
		t.Fatal("deferred intent did not recover", out, e)
	}
}
func TestIntegrityScheduleCredentialExpiryAndRevocationBlockUntilReauthorized(t *testing.T) {
	for _, mode := range []string{"revoked", "expired"} {
		t.Run(mode, func(t *testing.T) {
			db, ctx, admin, worker, workerToken, _ := jobFixture(t)
			configureSchedule(t, db, ctx, admin, "sample", "auth-create", scheduleInput())
			token, e := crypt.Token()
			if e != nil {
				t.Fatal(e)
			}
			if e = Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), admin.Tenant, "replacement", "admin", token, time.Now().Add(time.Hour)); e != nil {
				t.Fatal(e)
			}
			replacement, e := db.Authenticate(ctx, token)
			if e != nil {
				t.Fatal(e)
			}
			owner, e := pgx.Connect(ctx, os.Getenv("CRATECTL_OWNER_DSN"))
			if e != nil {
				t.Fatal(e)
			}
			defer owner.Close(ctx)
			query := `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`
			if mode == "expired" {
				query = `UPDATE cratectl_private.tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE hash=$1`
			}
			if _, e = owner.Exec(ctx, query, admin.CredentialHash); e != nil {
				t.Fatal(e)
			}
			out, e := db.DispatchIntegritySchedule(ctx, worker)
			if e != nil || out.State != "requester_authorization_unavailable" {
				t.Fatal("revoked requester scheduled work", out, e)
			}
			current, e := db.IntegritySchedule(ctx, replacement, "sample")
			if e != nil || !current.Blocked || current.LastJob != "" {
				t.Fatal("missing blocked state", current, e)
			}
			if _, e = db.DispatchIntegritySchedule(ctx, worker); !errors.Is(e, ErrNotFound) {
				t.Fatal("blocked schedule kept admitting", e)
			}
			input := scheduleInput()
			input.ExpectedRevision = current.Revision
			configureSchedule(t, db, ctx, replacement, "sample", "reauthorize", input)
			out, e = db.DispatchIntegritySchedule(ctx, worker)
			if e != nil || out.State != "admitted" {
				t.Fatal(out, e)
			}
			rows, _, e := db.IntegrityScheduleHistory(ctx, replacement, "sample", 0, 100)
			if e != nil || len(rows) != 2 {
				t.Fatal(rows, e)
			}
			raw, _ := json.Marshal(rows)
			if strings.Contains(string(raw), admin.CredentialHash) || strings.Contains(string(raw), replacement.CredentialHash) || strings.Contains(string(raw), token) || strings.Contains(string(raw), workerToken) {
				t.Fatal("private authorization fence leaked")
			}
			if _, e = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, worker.CredentialHash); e != nil {
				t.Fatal(e)
			}
			if _, e = db.DispatchIntegritySchedule(ctx, worker); !errors.Is(e, ErrUnauthenticated) {
				t.Fatal("revoked worker entered scheduler", e)
			}

		})
	}
}

func TestIntegrityScheduleTenantIsolationAndImmutableReceipts(t *testing.T) {
	db, ctx, a, worker, _, _ := jobFixture(t)
	_, _, b, _, _, _ := jobFixture(t)
	configureSchedule(t, db, ctx, a, "shared-name", "tenant-a", scheduleInput())
	input := scheduleInput()
	input.SampleSize = 1
	configureSchedule(t, db, ctx, b, "shared-name", "tenant-b", input)
	if _, e := db.DispatchIntegritySchedule(ctx, worker); e != nil {
		t.Fatal(e)
	}
	x, e := db.IntegritySchedule(ctx, b, "shared-name")
	if e != nil || x.SampleSize != 1 || x.LastJob != "" {
		t.Fatal("schedule tenant collision", x, e)
	}
	runs, more, e := db.IntegrityScheduleRuns(ctx, b, "shared-name", 0, 100)
	if e != nil || more || len(runs) != 0 {
		t.Fatal("cross-tenant run", runs, e)
	}
	reader := a
	reader.Role = "reader"
	if _, _, e = db.IntegritySchedules(ctx, reader, "", 10); !errors.Is(e, ErrDenied) {
		t.Fatal("reader saw schedule authority", e)
	}
	for _, table := range []string{"integrity_schedule_revisions", "integrity_schedule_runs"} {
		e = db.Tx(ctx, a, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE cratectl.`+table+` SET revision=revision`)
			return e
		})
		if e == nil {
			t.Fatal("immutable receipts changed", table)
		}
	}
	var n int
	if e = db.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.integrity_schedules`).Scan(&n); e != nil || n != 0 {
		t.Fatal("unscoped runtime bypassed RLS", n, e)
	}
}
func TestIntegrityScheduleConfigurationAndDispatchRollbackWithJournal(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	seedScheduleBindings(t, db, ctx, admin)
	// Fill the event lane so a configuration receipt cannot enqueue its intent.
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.SetIntegritySchedule(ctx, admin, "sample", "config-rollback", "config-rollback", scheduleInput(), 100); !errors.Is(e, ErrQueueFull) {
		t.Fatal("configuration acknowledged without outbox", e)
	}
	if _, e := db.IntegritySchedule(ctx, admin, "sample"); !errors.Is(e, ErrNotFound) {
		t.Fatal("partial configuration retained", e)
	}
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=100000 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	before := configureSchedule(t, db, ctx, admin, "sample", "config-rollback", scheduleInput())
	owner, e := pgx.Connect(ctx, os.Getenv("CRATECTL_OWNER_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	function := pgx.Identifier{"cratectl_private", "schedule_fault_" + strings.ReplaceAll(admin.Tenant, "-", "_")}.Sanitize()
	trigger := pgx.Identifier{"schedule_fault_" + strings.ReplaceAll(admin.Tenant, "-", "_")}.Sanitize()
	ddl := `CREATE FUNCTION ` + function + `() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.tenant='` + admin.Tenant + `' AND NEW.payload::jsonb->>'kind'='storage.schedule.admitted' THEN RAISE EXCEPTION 'owned schedule journal fault'; END IF; RETURN NEW; END$$; CREATE TRIGGER ` + trigger + ` BEFORE INSERT ON cratectl.events FOR EACH ROW EXECUTE FUNCTION ` + function + `()`
	if _, e = owner.Exec(ctx, ddl); e != nil {
		t.Fatal(e)
	}
	cleanup := func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e := owner.Exec(c, `DROP TRIGGER IF EXISTS `+trigger+` ON cratectl.events; DROP FUNCTION IF EXISTS `+function+`() `)
		if e != nil {
			t.Error(e)
		}
	}
	defer cleanup()
	if _, e = db.DispatchIntegritySchedule(ctx, worker); e == nil {
		t.Fatal("dispatch acknowledged without journal receipt")
	}
	after, e := db.IntegritySchedule(ctx, admin, "sample")
	if e != nil || after.Cursor != before.Cursor || after.LastJob != "" || !after.NextDueAt.Equal(before.NextDueAt) {
		t.Fatal("lost receipt advanced schedule", after, e)
	}
	runs, _, e := db.IntegrityScheduleRuns(ctx, admin, "sample", 0, 100)
	if e != nil || len(runs) != 0 {
		t.Fatal("uncommitted run visible", runs, e)
	}
	var items int
	e = db.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.sweep_items`).Scan(&items)
	})
	if e != nil || items != 0 {
		t.Fatal("partial sample retained", items, e)
	}
	cleanup()
	out, e := db.DispatchIntegritySchedule(ctx, worker)
	if e != nil || out.State != "admitted" {
		t.Fatal("retry could not admit original slot", out, e)
	}
}

func TestIntegrityScheduleRequesterExpiryDuringAdmissionRollsBackAllEffects(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	configureSchedule(t, db, ctx, admin, "expiry", "expiry-create", scheduleInput())
	owner, e := pgx.Connect(ctx, os.Getenv("CRATECTL_OWNER_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	function := pgx.Identifier{"cratectl_private", "schedule_expiry_" + strings.ReplaceAll(admin.Tenant, "-", "_")}.Sanitize()
	trigger := pgx.Identifier{"schedule_expiry_" + strings.ReplaceAll(admin.Tenant, "-", "_")}.Sanitize()
	// Deterministically expire the original credential after snapshot preparation
	// and its first recheck, at the final admission write. This represents a real
	// clock deadline crossing without a timing-dependent sleep in the regression.
	ddl := `CREATE FUNCTION ` + function + `() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN IF NEW.tenant='` + admin.Tenant + `' THEN UPDATE cratectl_private.tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE hash='` + admin.CredentialHash + `'; END IF; RETURN NEW; END$$; CREATE TRIGGER ` + trigger + ` BEFORE INSERT ON cratectl.integrity_schedule_runs FOR EACH ROW EXECUTE FUNCTION ` + function + `()`
	if _, e = owner.Exec(ctx, ddl); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_, e := owner.Exec(ctx, `DROP TRIGGER IF EXISTS `+trigger+` ON cratectl.integrity_schedule_runs;DROP FUNCTION IF EXISTS `+function+`() `)
		if e != nil {
			t.Error(e)
		}
	}()
	out, dispatchErr := db.DispatchIntegritySchedule(ctx, worker)
	// Restore the test credential so the operator can inspect actual durable state.
	if _, e = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET expires_at=clock_timestamp()+interval '1 hour' WHERE hash=$1`, admin.CredentialHash); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(dispatchErr, ErrScheduleAuthorization) {
		t.Fatal("expired requester admitted a run", out, dispatchErr)
	}
	current, e := db.IntegritySchedule(ctx, admin, "expiry")
	if e != nil || current.LastJob != "" || current.Cursor != (SampleCursor{}) {
		t.Fatal("expired admission retained effects", current, e)
	}
	runs, _, e := db.IntegrityScheduleRuns(ctx, admin, "expiry", 0, 100)
	if e != nil || len(runs) != 0 {
		t.Fatal("expired run receipt survived", runs, e)
	}
}

func TestIntegrityScheduleSamplesRetiredHeldDeniedAndConflictingUploadBindings(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	seedScheduleBindings(t, db, ctx, admin)
	e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,decision) VALUES($1,'packages','size-conflict',$2,4,'application/octet-stream','denied')`, admin.Tenant, strings.Repeat("a", 64)); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,deleted,revision,hold_reason,reason,actor,change_sequence) VALUES($1,'packages','file-0',$2,true,1,'Retain held evidence','Owned retained fixture','operator',1)`, admin.Tenant, strings.Repeat("a", 64)); e != nil {
			return e
		}
		if e := CreateRepository(ctx, tx, admin, Repository{Name: "images", Format: "oci"}); e != nil {
			return e
		}
		id := strings.Repeat("x", 43)
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.uploads(tenant,repository,image,id,state) VALUES($1,'images','app',$2,'cancelled')`, admin.Tenant, id); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.upload_parts(tenant,upload_id,offset_bytes,digest,size) VALUES($1,$2,0,$3,5)`, admin.Tenant, id, strings.Repeat("9", 64))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	input := scheduleInput()
	input.SampleSize = 1
	configureSchedule(t, db, ctx, admin, "bounded", "bounded-conflict", input)
	out, e := db.DispatchIntegritySchedule(ctx, worker)
	if e != nil {
		t.Fatal(e)
	}
	items, _, e := db.SweepItems(ctx, admin, out.Job, 0, 100)
	if e != nil || len(items) != 1 || !items[0].ReferenceConflict || items[0].Digest != strings.Repeat("a", 64) || items[0].ArtifactReferences != 2 {
		t.Fatal("limit hid retained conflicts or aliases", items, e)
	}
	finishScheduleSample(t, db, ctx, worker, out.Job, false)
	runs, _, e := db.IntegrityScheduleRuns(ctx, admin, "bounded", 0, 100)
	if e != nil || len(runs) != 1 || runs[0].SampleClean || runs[0].Progress.Issues != 1 {
		t.Fatal("conflicting reference became clean", runs, e)
	}
	input.Repository = ""
	input.SampleSize = 100
	configureSchedule(t, db, ctx, admin, "tenant-wide", "all-bindings", input)
	out, e = db.DispatchIntegritySchedule(ctx, worker)
	if e != nil {
		t.Fatal(e)
	}
	j, e := db.Job(ctx, admin, out.Job)
	if e != nil {
		t.Fatal(e)
	}
	progress, e := sweepProgress(j.Target)
	if e != nil || progress.Targets != 7 || progress.ArtifactReferences != 7 || progress.UploadParts != 1 {
		t.Fatal("retained bindings omitted", progress, e)
	}
	items, _, e = db.SweepItems(ctx, admin, out.Job, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	foundPart := false
	for _, item := range items {
		if item.Repository == "images" && item.UploadParts == 1 && strings.HasPrefix(item.Path, "oci-upload/") {
			foundPart = true
		}
	}
	if !foundPart {
		t.Fatal("retained cancelled upload part omitted")
	}
}

func TestIntegrityScheduleEmptyCaptureDoesNotClaimByteVerification(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	configureSchedule(t, db, ctx, admin, "empty", "empty-sample", scheduleInput())
	out, e := db.DispatchIntegritySchedule(ctx, worker)
	if e != nil {
		t.Fatal(e)
	}
	finishScheduleSample(t, db, ctx, worker, out.Job, false)
	runs, _, e := db.IntegrityScheduleRuns(ctx, admin, "empty", 0, 10)
	if e != nil || len(runs) != 1 {
		t.Fatal(runs, e)
	}
	if runs[0].Progress.Targets != 0 || !runs[0].SampleAssessed || runs[0].SampleClean {
		t.Fatal("empty capture claimed byte verification", runs[0])
	}
	detail, e := db.Sweep(ctx, admin, out.Job)
	if e != nil || detail["integrity_clean"] != false {
		t.Fatal("empty sample endpoint claimed verified bytes", detail, e)
	}
}

func TestIntegrityScheduleRunInspectionAndWorkerRejectMutableReceiptDrift(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	seedScheduleBindings(t, db, ctx, admin)
	configureSchedule(t, db, ctx, admin, "receipt", "receipt-create", scheduleInput())
	out, e := db.DispatchIntegritySchedule(ctx, worker)
	if e != nil {
		t.Fatal(e)
	}
	seq, task, e := ParseJobID(out.Job)
	if e != nil {
		t.Fatal(e)
	}
	original, e := db.Job(ctx, admin, out.Job)
	if e != nil {
		t.Fatal(e)
	}
	claimed, e := db.ClaimJob(ctx, worker, "integrity", "receipt-check", time.Minute)
	if e != nil || claimed.ID() != out.Job {
		t.Fatal("claim receipt fixture", e)
	}
	item, empty, e := db.NextSweepItem(ctx, worker, claimed)
	if e != nil || empty {
		t.Fatal("valid original receipt rejected", e)
	}
	for _, test := range []struct{ name, expression string }{
		{"revision", `jsonb_set(payload,'{sampling,revision}','2'::jsonb)`},
		{"due slot", `jsonb_set(payload,'{sampling,due_at}','"2001-01-01T00:00:00Z"'::jsonb)`},
		{"coalesced intervals", `jsonb_set(payload,'{sampling,coalesced_intervals}','1'::jsonb)`},
		{"schedule", `jsonb_set(payload,'{sampling,schedule}','"another-name"'::jsonb)`},
		{"missing sampling identity", `payload-'sampling'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET payload=`+test.expression+` WHERE sequence=$1 AND task=$2`, seq, task)
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET payload=$3 WHERE sequence=$1 AND task=$2`, seq, task, original.Target)
					return e
				}); e != nil {
					t.Error(e)
				}
			}()
			if _, _, e = db.IntegrityScheduleRuns(ctx, admin, "receipt", 0, 100); !errors.Is(e, ErrScheduleEvidence) {
				t.Fatal("mutable progress replaced immutable run identity", e)
			}
			if _, e = db.Sweep(ctx, admin, out.Job); !errors.Is(e, ErrScheduleEvidence) {
				t.Fatal("sample detail accepted receipt drift", e)
			}
			if _, _, e = db.SweepItems(ctx, admin, out.Job, 0, 100); !errors.Is(e, ErrScheduleEvidence) {
				t.Fatal("sample target page accepted receipt drift", e)
			}
			if _, _, e = db.NextSweepItem(ctx, worker, claimed); !errors.Is(e, ErrScheduleEvidence) {
				t.Fatal("worker read accepted receipt drift", e)
			}
			if _, e = db.FinishSweepItem(ctx, worker, claimed, item, "verified"); !errors.Is(e, ErrScheduleEvidence) {
				t.Fatal("worker completion accepted receipt drift", e)
			}
			observations, _, e := db.JobObservations(ctx, admin, out.Job, 0, 100)
			if e != nil || len(observations) != 0 {
				t.Fatal("receipt drift produced an observation", e)
			}
		})
	}
	runs, _, e := db.IntegrityScheduleRuns(ctx, admin, "receipt", 0, 100)
	if e != nil || len(runs) != 1 || runs[0].Revision != 1 {
		t.Fatal("original immutable receipt did not recover", e)
	}
}
