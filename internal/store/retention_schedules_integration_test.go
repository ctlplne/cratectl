//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func retentionScheduleInput() RetentionScheduleRequest {
	return RetentionScheduleRequest{RetentionScheduleSettings: RetentionScheduleSettings{IntervalSeconds: 60, MaxTargets: 100, Enabled: true, Reason: "Explicit future bounded retirement"}, ExpectedPolicyRevision: 1, AuthorizeFutureRetirements: true, RunImmediately: true}
}
func configureRetentionSchedule(t *testing.T, db *Store, ctx context.Context, i Identity, r RetentionScheduleRequest, key string) RetentionSchedule {
	t.Helper()
	v, e := db.SetRetentionSchedule(ctx, i, "retained", "age", key, key, r, 100)
	if e != nil {
		t.Fatal(e)
	}
	var out RetentionSchedule
	if json.Unmarshal(v.Body, &out) != nil {
		t.Fatal("schedule response decoding")
	}
	return out
}
func dueRetentionSchedule(t *testing.T, owner *pgx.Conn, i Identity, ago int64) {
	t.Helper()
	if _, e := owner.Exec(context.Background(), `UPDATE cratectl.retention_schedules SET next_due_at=clock_timestamp()-$2::bigint*interval '1 second',retry_at='epoch' WHERE tenant=$1 AND repository='retained' AND name='age'`, i.Tenant, ago); e != nil {
		t.Fatal(e)
	}
}
func TestRetentionSchedulePreviewRevisionAndReplayPreserveApproval(t *testing.T) {
	db, ctx, admin, _, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	retentionManifest(t, db, ctx, admin, "app", "preview", 3600, nil)
	r := retentionScheduleInput()
	r.DryRun = true
	preview, e := db.SetRetentionSchedule(ctx, admin, "retained", "age", "", "", r, 100)
	if e != nil || preview.Status != 200 {
		t.Fatal("schedule preview", e)
	}
	if _, e = db.RetentionSchedule(ctx, admin, "retained", "age"); !errors.Is(e, ErrNotFound) {
		t.Fatal("preview wrote schedule", e)
	}
	if retentionCount(t, db, ctx, admin, "retention_runs") != 0 {
		t.Fatal("configuration preview admitted retirement")
	}
	r.DryRun = false
	v, e := db.SetRetentionSchedule(ctx, admin, "retained", "age", "create-schedule", "same-body", r, 100)
	if e != nil || v.Status != 201 {
		t.Fatal("schedule apply", e)
	}
	if strings.Contains(string(v.Body), admin.CredentialHash) {
		t.Fatal("private authorizing hash exposed")
	}
	replay, e := db.SetRetentionSchedule(ctx, admin, "retained", "age", "create-schedule", "same-body", r, 1)
	if e != nil || !replay.Replay || string(replay.Body) != string(v.Body) {
		t.Fatal("unchanged request cannot confirm original operation after ceiling change", e)
	}
	if _, e = db.SetRetentionSchedule(ctx, admin, "retained", "age", "create-schedule", "changed-body", r, 100); !errors.Is(e, ErrConflict) {
		t.Fatal("changed idempotent request accepted", e)
	}
	if _, e = db.SetRetentionSchedule(ctx, admin, "retained", "age", "stale-schedule", "stale", r, 100); !errors.Is(e, ErrRetentionScheduleChanged) {
		t.Fatal("stale revision accepted", e)
	}
	r.ExpectedRevision = 1
	r.Enabled = false
	r.RunImmediately = false
	r.AuthorizeFutureRetirements = false
	out := configureRetentionSchedule(t, db, ctx, admin, r, "pause-schedule")
	if out.Revision != 2 || out.Enabled || out.AuthorizeFutureRetirements {
		t.Fatal("pause retained future approval")
	}
	history, more, e := db.RetentionScheduleHistory(ctx, admin, "retained", "age", 0, 1)
	if e != nil || !more || len(history) != 1 {
		t.Fatal("bounded history", e)
	}
	history, more, e = db.RetentionScheduleHistory(ctx, admin, "retained", "age", 1, 1)
	if e != nil || more || len(history) != 1 {
		t.Fatal("history continuation", e)
	}
}
func TestRetentionScheduleConcurrentCaptureCoalescesAndDoesNotOverlap(t *testing.T) {
	db, ctx, admin, w, owner := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	retentionManifest(t, db, ctx, admin, "app", "first", 3600, nil)
	retentionManifest(t, db, ctx, admin, "app", "second", 3600, nil)
	configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "cadence-config")
	dueRetentionSchedule(t, owner, admin, 185)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := []RetentionScheduleDispatch{}
	failures := []error{}
	for n := 0; n < 6; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := db.DispatchRetentionSchedule(ctx, w)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				admitted = append(admitted, v)
			} else if !errors.Is(e, ErrNotFound) {
				failures = append(failures, e)
			}
		}()
	}
	wg.Wait()
	if len(failures) != 0 || len(admitted) != 1 || admitted[0].State != "admitted" {
		t.Fatal("duplicate or failed due admission", len(admitted), failures)
	}
	id := admitted[0].Job
	detail, e := db.RetentionRun(ctx, admin, id)
	if e != nil {
		t.Fatal(e)
	}
	plan := detail["plan"].(RetentionPlan)
	if plan.Schedule == nil || plan.Schedule.CoalescedIntervals != 3 || plan.Targets != 2 {
		t.Fatal("incorrect immutable cadence capture")
	}
	current, e := db.RetentionSchedule(ctx, admin, "retained", "age")
	if e != nil || !current.NextDueAt.After(plan.EvaluatedAt) || current.NextDueAt.Sub(plan.EvaluatedAt) > time.Minute {
		t.Fatal("cadence did not advance to first future slot", e)
	}
	dueRetentionSchedule(t, owner, admin, 60)
	before, _ := db.RetentionSchedule(ctx, admin, "retained", "age")
	deferred, e := db.DispatchRetentionSchedule(ctx, w)
	if e != nil || deferred.State != "previous_run_active" {
		t.Fatal("active run overlapped", deferred.State, e)
	}
	after, _ := db.RetentionSchedule(ctx, admin, "retained", "age")
	if !after.NextDueAt.Equal(before.NextDueAt) || retentionCount(t, db, ctx, admin, "retention_schedule_runs") != 1 {
		t.Fatal("deferral advanced or duplicated due slot")
	}
	retentionDrain(t, db, ctx, w, id)
	dueRetentionSchedule(t, owner, admin, 0)
	next, e := db.DispatchRetentionSchedule(ctx, w)
	if e != nil || next.State != "admitted" {
		t.Fatal("next due slot did not recover", e)
	}
	retentionDrain(t, db, ctx, w, next.Job)
	detail, e = db.RetentionRun(ctx, admin, next.Job)
	if e != nil || detail["plan"].(RetentionPlan).Targets != 0 || detail["bytes_reclaimed"] != 0 {
		t.Fatal("empty capture invented work", e)
	}
	runs, more, e := db.RetentionScheduleRuns(ctx, admin, "retained", "age", 0, 1)
	if e != nil || !more || len(runs) != 1 || runs[0].Job != id {
		t.Fatal("scheduled run pagination", e)
	}
}
func TestRetentionSchedulePauseFencesPendingEffectsAndPreservesManualApproval(t *testing.T) {
	db, ctx, admin, w, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	retentionManifest(t, db, ctx, admin, "app", "a", 3600, nil)
	retentionManifest(t, db, ctx, admin, "app", "b", 3600, nil)
	configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "pause-config")
	run, e := db.DispatchRetentionSchedule(ctx, w)
	if e != nil {
		t.Fatal(e)
	}
	j, e := db.ClaimJob(ctx, w, "maintenance", "pause-worker", time.Minute)
	if e != nil || j.ID() != run.Job {
		t.Fatal("claim", e)
	}
	if state, e := db.StepRetention(ctx, w, j); e != nil || state != "pending" {
		t.Fatal("first committed target", state, e)
	}
	r := retentionScheduleInput()
	r.ExpectedRevision = 1
	r.Enabled = false
	r.RunImmediately = false
	r.AuthorizeFutureRetirements = false
	configureRetentionSchedule(t, db, ctx, admin, r, "pause-new-revision")
	j, e = db.ClaimJob(ctx, w, "maintenance", "pause-worker", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.StepRetention(ctx, w, j); !errors.Is(e, ErrRetentionScheduleChanged) {
		t.Fatal("paused approval retained execution authority", e)
	}
	if _, e = db.FailJob(ctx, w, j, "retention_schedule_changed", true); e != nil {
		t.Fatal(e)
	}
	detail, e := db.RetentionRun(ctx, admin, run.Job)
	if e != nil || detail["retired"] != int64(1) {
		t.Fatal("pause lost committed outcomes", e)
	}
	manual := retentionAdmit(t, db, ctx, admin, retentionPreviewFixture(t, db, ctx, admin), "independent-manual-approval")
	retentionDrain(t, db, ctx, w, manual)
	detail, e = db.RetentionRun(ctx, admin, manual)
	if e != nil || detail["plan"].(RetentionPlan).Schedule != nil || detail["retired"] != int64(1) {
		t.Fatal("manual approval inherited schedule", e)
	}
}
func TestRetentionScheduleRequesterLossBlocksUntilExplicitReauthorization(t *testing.T) {
	for _, mode := range []string{"expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			db, ctx, admin, w, owner := retentionFixture(t)
			retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
			retentionManifest(t, db, ctx, admin, "app", mode, 3600, nil)
			token, _ := crypt.Token()
			if e := Provision(ctx, owner.Config().ConnString(), admin.Tenant, "recovery", "admin", token, time.Now().Add(time.Hour)); e != nil {
				t.Fatal(e)
			}
			recovery, e := db.Authenticate(ctx, token)
			if e != nil {
				t.Fatal(e)
			}
			configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "requester-config")
			query := `UPDATE cratectl_private.tokens SET expires_at='epoch' WHERE hash=$1`
			if mode == "revoked" {
				query = `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`
			}
			if _, e = owner.Exec(ctx, query, admin.CredentialHash); e != nil {
				t.Fatal(e)
			}
			v, e := db.DispatchRetentionSchedule(ctx, w)
			if e != nil || v.State != "requester_authorization_unavailable" {
				t.Fatal("requester authority bypass", v.State, e)
			}
			current, e := db.RetentionSchedule(ctx, recovery, "retained", "age")
			if e != nil || !current.Blocked || current.LastJob != "" {
				t.Fatal("missing explicit blocked state", e)
			}
			if _, e = db.DispatchRetentionSchedule(ctx, w); !errors.Is(e, ErrNotFound) {
				t.Fatal("blocked schedule kept admitting", e)
			}
			r := retentionScheduleInput()
			r.ExpectedRevision = 1
			configureRetentionSchedule(t, db, ctx, recovery, r, "fresh-requester-approval")
			v, e = db.DispatchRetentionSchedule(ctx, w)
			if e != nil || v.State != "admitted" {
				t.Fatal("fresh authority could not resume", e)
			}
			retentionDrain(t, db, ctx, w, v.Job)
		})
	}
}
func TestRetentionSchedulePolicyAndSourceChangesRequireNewApproval(t *testing.T) {
	for _, mode := range []string{"policy", "source"} {
		t.Run(mode, func(t *testing.T) {
			db, ctx, admin, w, owner := retentionFixture(t)
			retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
			retentionManifest(t, db, ctx, admin, "app", mode, 3600, nil)
			configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "binding-config")
			expected := mode + "_changed"
			r := retentionScheduleInput()
			r.ExpectedRevision = 1
			if mode == "policy" {
				p := retentionPolicyInput()
				p.ExpectedRevision = 1
				p.Reason = "New explicit policy revision"
				retentionConfigure(t, db, ctx, admin, p)
				r.ExpectedPolicyRevision = 2
			} else {
				if _, e := owner.Exec(ctx, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE tenant=$1 AND name='retained'`, admin.Tenant); e != nil {
					t.Fatal(e)
				}
				r.ExpectedSourceRevision = 1
			}
			out, e := db.DispatchRetentionSchedule(ctx, w)
			if e != nil || out.State != expected {
				t.Fatal("changed binding retained future authority", out.State, e)
			}
			configureRetentionSchedule(t, db, ctx, admin, r, "binding-renewal")
			out, e = db.DispatchRetentionSchedule(ctx, w)
			if e != nil || out.State != "admitted" {
				t.Fatal("new bound approval failed", e)
			}
			retentionDrain(t, db, ctx, w, out.Job)
		})
	}
}
func TestRetentionScheduleBudgetAndQueueDeferralsKeepDueIntent(t *testing.T) {
	db, ctx, admin, w, owner := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	retentionManifest(t, db, ctx, admin, "app", "a", 3600, nil)
	retentionManifest(t, db, ctx, admin, "app", "b", 3600, nil)
	r := retentionScheduleInput()
	r.MaxTargets = 1
	configureRetentionSchedule(t, db, ctx, admin, r, "bounded-config")
	before, _ := db.RetentionSchedule(ctx, admin, "retained", "age")
	out, e := db.DispatchRetentionSchedule(ctx, w)
	if e != nil || out.State != "plan_budget_exceeded" {
		t.Fatal("partial bounded capture admitted", out.State, e)
	}
	after, _ := db.RetentionSchedule(ctx, admin, "retained", "age")
	if !after.NextDueAt.Equal(before.NextDueAt) || retentionCount(t, db, ctx, admin, "retention_runs") != 0 {
		t.Fatal("budget deferral lost due slot")
	}
	r.ExpectedRevision = 1
	r.MaxTargets = 100
	configureRetentionSchedule(t, db, ctx, admin, r, "larger-approved-budget")
	if _, e = owner.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1 WHERE tenant=$1 AND queue='events'`, admin.Tenant); e != nil {
		t.Fatal(e)
	}
	out, e = db.DispatchRetentionSchedule(ctx, w)
	if e != nil || out.State != "events_queue_full" {
		t.Fatal("outbox pressure bypassed", out.State, e)
	}
	if retentionCount(t, db, ctx, admin, "retention_items") != 0 || retentionCount(t, db, ctx, admin, "retention_schedule_runs") != 0 {
		t.Fatal("queue deferral partially captured work")
	}
	if _, e = owner.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1000 WHERE tenant=$1 AND queue='events'`, admin.Tenant); e != nil {
		t.Fatal(e)
	}
	dueRetentionSchedule(t, owner, admin, 0)
	out, e = db.DispatchRetentionSchedule(ctx, w)
	if e != nil || out.State != "admitted" {
		t.Fatal("capacity recovery", out.State, e)
	}
}
func TestRetentionScheduleFinalJournalAndRequesterFailureRollBackAdmission(t *testing.T) {
	for _, fault := range []string{"journal", "late_requester"} {
		t.Run(fault, func(t *testing.T) {
			db, ctx, admin, w, owner := retentionFixture(t)
			retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
			retentionManifest(t, db, ctx, admin, "app", fault, 3600, nil)
			configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "atomic-config")
			before, _ := db.RetentionSchedule(ctx, admin, "retained", "age")
			body := `RAISE EXCEPTION 'owned scheduled retention journal fault';`
			if fault == "late_requester" {
				body = `UPDATE cratectl_private.tokens SET expires_at='epoch' WHERE hash='` + admin.CredentialHash + `';`
			}
			if _, e := owner.Exec(ctx, `CREATE FUNCTION public.retention_schedule_fault()RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN IF NEW.payload::jsonb->>'kind'='repository.retention.schedule.admitted' THEN `+body+` END IF;RETURN NEW;END$$;CREATE TRIGGER retention_schedule_fault BEFORE INSERT ON cratectl.events FOR EACH ROW EXECUTE FUNCTION public.retention_schedule_fault()`); e != nil {
				t.Fatal(e)
			}
			if _, e := db.DispatchRetentionSchedule(ctx, w); e == nil || fault == "late_requester" && !errors.Is(e, ErrRetentionAuthorization) {
				t.Fatal("admission survived final-write authority/journal fault", e)
			}
			after, e := db.RetentionSchedule(ctx, admin, "retained", "age")
			if e != nil || !after.NextDueAt.Equal(before.NextDueAt) || after.LastJob != "" {
				t.Fatal("due cursor survived rollback", e)
			}
			for _, table := range []string{"retention_runs", "retention_items", "retention_schedule_runs"} {
				if retentionCount(t, db, ctx, admin, table) != 0 {
					t.Fatal("partial admission survived", table)
				}
			}
			if _, e = owner.Exec(ctx, `DROP TRIGGER retention_schedule_fault ON cratectl.events;DROP FUNCTION public.retention_schedule_fault()`); e != nil {
				t.Fatal(e)
			}
			if v, e := db.DispatchRetentionSchedule(ctx, w); e != nil || v.State != "admitted" {
				t.Fatal("same due intent failed after repaired fault", e)
			}
		})
	}
}
func TestRetentionScheduleInspectionAndExecutionRejectContradictoryReceipts(t *testing.T) {
	db, ctx, admin, w, owner := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	retentionManifest(t, db, ctx, admin, "app", "receipt", 3600, nil)
	configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "receipt-config")
	out, e := db.DispatchRetentionSchedule(ctx, w)
	if e != nil {
		t.Fatal(e)
	}
	seq, task, _ := ParseJobID(out.Job)
	if _, e = owner.Exec(ctx, `UPDATE cratectl.jobs SET payload='{}' WHERE tenant=$1 AND sequence=$2 AND task=$3`, admin.Tenant, seq, task); e != nil {
		t.Fatal(e)
	}
	if value, e := db.RetentionRun(ctx, admin, out.Job); e != nil || value["plan"].(RetentionPlan).Schedule == nil {
		t.Fatal("mutable projection replaced immutable approval", e)
	}
	var original []byte
	if e = owner.QueryRow(ctx, `SELECT plan FROM cratectl.retention_runs WHERE tenant=$1 AND sequence=$2 AND task=$3`, admin.Tenant, seq, task).Scan(&original); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(ctx, `UPDATE cratectl.retention_runs SET plan=plan-'schedule' WHERE tenant=$1 AND sequence=$2 AND task=$3`, admin.Tenant, seq, task); e != nil {
		t.Fatal(e)
	}
	if _, e = db.RetentionRun(ctx, admin, out.Job); !errors.Is(e, ErrRetentionInput) {
		t.Fatal("missing schedule marker accepted", e)
	}
	if _, _, e = db.RetentionRuns(ctx, admin, "retained", "age", 0, 100); !errors.Is(e, ErrRetentionInput) {
		t.Fatal("policy history accepted missing provenance", e)
	}
	j, e := db.ClaimJob(ctx, w, "maintenance", "receipt-worker", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.StepRetention(ctx, w, j); !errors.Is(e, ErrRetentionInput) {
		t.Fatal("worker ignored contradictory receipt", e)
	}
	if retentionCount(t, db, ctx, admin, "retention_observations") != 0 {
		t.Fatal("contradictory receipt produced target effects")
	}
	if _, e = owner.Exec(ctx, `UPDATE cratectl.retention_runs SET plan=$4 WHERE tenant=$1 AND sequence=$2 AND task=$3`, admin.Tenant, seq, task, original); e != nil {
		t.Fatal(e)
	}
	if state, e := db.StepRetention(ctx, w, j); e != nil || state != "succeeded" {
		t.Fatal("owned receipt restoration did not replay", state, e)
	}
}

func TestRetentionScheduleTenantIsolationAndImmutableHistory(t *testing.T) {
	db, ctx, admin, w, owner := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "tenant-one-schedule")
	token, _ := crypt.Token()
	if e := Provision(ctx, owner.Config().ConnString(), "scheduled-other", "other-admin", "admin", token, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	other, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, other, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, other, Repository{Name: "retained", Format: "oci"})
	}); e != nil {
		t.Fatal(e)
	}
	retentionConfigure(t, db, ctx, other, retentionPolicyInput())
	configureRetentionSchedule(t, db, ctx, other, retentionScheduleInput(), "tenant-two-schedule")
	if e = db.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.retention_schedules`).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			t.Fatal("cross-tenant schedule enumeration", n)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	out, e := db.DispatchRetentionSchedule(ctx, w)
	if e != nil || out.State != "admitted" {
		t.Fatal(e)
	}
	history, _, e := db.RetentionScheduleHistory(ctx, other, "retained", "age", 0, 100)
	if e != nil || len(history) != 1 || strings.Contains(string(history[0]), admin.CredentialHash) {
		t.Fatal("history tenant/credential boundary", e)
	}
	if rows, _, e := db.RetentionScheduleRuns(ctx, other, "retained", "age", 0, 100); e != nil || len(rows) != 0 {
		t.Fatal("scheduled job crossed tenants", e)
	}
	e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.retention_schedule_revisions(tenant,repository,name,revision,configuration)VALUES('scheduled-other','retained','age',999,'{}')`)
		return e
	})
	var pe *pgconn.PgError
	if !errors.As(e, &pe) || pe.Code != "42501" {
		t.Fatal("cross-tenant immutable history insert accepted", e)
	}
}

func TestRetentionScheduleRejectsCrossLinkedPolicyAndRequesterEvidence(t *testing.T) {
	for _, fault := range []string{"policy_link", "requester_actor"} {
		t.Run(fault, func(t *testing.T) {
			db, ctx, admin, w, owner := retentionFixture(t)
			retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
			retentionManifest(t, db, ctx, admin, "app", "identity-probe", 3600, nil)
			approved := configureRetentionSchedule(t, db, ctx, admin, retentionScheduleInput(), "identity-schedule")
			if fault == "policy_link" {
				if _, e := db.SetRetentionPolicy(ctx, admin, "retained", "other", "other-policy", "other-policy", retentionPolicyInput()); e != nil {
					t.Fatal(e)
				}
				if _, e := db.SetRetentionSchedule(ctx, admin, "retained", "other", "other-schedule", "other-schedule", retentionScheduleInput(), 100); e != nil {
					t.Fatal(e)
				}
			}
			out, e := db.DispatchRetentionSchedule(ctx, w)
			if e != nil {
				t.Fatal(e)
			}
			seq, task, _ := ParseJobID(out.Job)
			if fault == "policy_link" {
				copied := approved
				copied.Policy.Name = "other"
				raw, _ := json.Marshal(copied)
				if _, e = owner.Exec(ctx, `UPDATE cratectl.retention_schedule_revisions SET configuration=$2 WHERE tenant=$1 AND repository='retained' AND name='other' AND revision=1`, admin.Tenant, raw); e != nil {
					t.Fatal(e)
				}
				if _, e = owner.Exec(ctx, `UPDATE cratectl.retention_schedule_runs SET name='other' WHERE tenant=$1 AND sequence=$2 AND task=$3`, admin.Tenant, seq, task); e != nil {
					t.Fatal(e)
				}
			} else {
				copied := approved
				copied.AuthorizedActor = "altered-actor"
				raw, _ := json.Marshal(copied)
				if _, e = owner.Exec(ctx, `UPDATE cratectl.retention_schedule_revisions SET configuration=$2 WHERE tenant=$1 AND repository='retained' AND name='age' AND revision=1`, admin.Tenant, raw); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = db.RetentionRun(ctx, admin, out.Job); !errors.Is(e, ErrRetentionInput) {
				t.Fatal("run inspection accepted contradictory policy/requester identity", e)
			}
			if _, _, e = db.RetentionRuns(ctx, admin, "retained", "age", 0, 100); !errors.Is(e, ErrRetentionInput) {
				t.Fatal("history accepted contradictory identity", e)
			}
			j, e := db.ClaimJob(ctx, w, "maintenance", "identity-worker", time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.StepRetention(ctx, w, j); !errors.Is(e, ErrRetentionInput) {
				t.Fatal("worker accepted contradictory identity", e)
			}
			if retentionCount(t, db, ctx, admin, "retention_observations") != 0 {
				t.Fatal("contradictory evidence produced retirement")
			}
		})
	}
}
