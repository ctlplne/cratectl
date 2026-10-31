// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type RetentionScheduleReceipt struct {
	Revision           int64     `json:"revision"`
	DueAt              time.Time `json:"due_at"`
	CoalescedIntervals int64     `json:"coalesced_intervals"`
}
type RetentionScheduleDispatch struct {
	Repository string `json:"repository"`
	Policy     string `json:"policy"`
	State      string `json:"state"`
	Job        string `json:"job,omitempty"`
}

func deferRetentionSchedule(ctx context.Context, tx pgx.Tx, i WorkerIdentity, s RetentionSchedule, code string, blocked bool) (RetentionScheduleDispatch, error) {
	out := RetentionScheduleDispatch{Repository: s.Repository, Policy: s.Policy.Name, State: code}
	_, e := tx.Exec(ctx, `UPDATE cratectl.retention_schedules SET blocked=$3,last_error=$4,retry_at=clock_timestamp()+interval '30 seconds' WHERE repository=$1 AND name=$2`, s.Repository, s.Policy.Name, blocked, code)
	if e == nil && (s.LastError != code || s.Blocked != blocked) {
		e = appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "repository.retention.schedule.deferred", map[string]any{"repository": s.Repository, "policy": s.Policy.Name, "revision": s.Revision, "due_at": s.NextDueAt, "reason": code, "blocked": blocked}, false)
	}
	return out, e
}
func (s *Store) DispatchRetentionSchedule(ctx context.Context, i WorkerIdentity) (RetentionScheduleDispatch, error) {
	var out RetentionScheduleDispatch
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		var repo, name string
		e := tx.QueryRow(ctx, `SELECT repository,name FROM cratectl.retention_schedules WHERE enabled AND NOT blocked AND next_due_at<=clock_timestamp() AND retry_at<=clock_timestamp() ORDER BY next_due_at,repository,name LIMIT 1`).Scan(&repo, &name)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		current, hash, e := retentionSchedule(ctx, tx, repo, name)
		if e != nil {
			return e
		}
		deferRun := func(code string, blocked bool) error {
			var e error
			out, e = deferRetentionSchedule(ctx, tx, i, current, code, blocked)
			return e
		}
		requester := Identity{Tenant: i.Tenant, Actor: current.AuthorizedActor, Role: "admin", CredentialHash: hash}
		if e = retentionRequester(ctx, tx, requester); errors.Is(e, ErrRetentionAuthorization) {
			return deferRun("requester_authorization_unavailable", true)
		} else if e != nil {
			return e
		}
		record, e := retentionRepository(ctx, tx, requester, repo)
		if errors.Is(e, ErrNotFound) || errors.Is(e, ErrDenied) || errors.Is(e, ErrRepositorySuspended) || errors.Is(e, ErrRepositoryRemoved) {
			return deferRun("repository_unavailable", false)
		}
		if e != nil {
			return e
		}
		policy, e := retentionPolicy(ctx, tx, repo, name)
		if e != nil {
			return e
		}
		if policy.Revision != current.Policy.Revision || !policy.Enabled {
			return deferRun("policy_changed", true)
		}
		if record.SourceRevision != current.SourceRevision {
			return deferRun("source_changed", true)
		}
		var active bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.retention_runs r JOIN cratectl.jobs j ON(j.tenant,j.sequence,j.task)=(r.tenant,r.sequence,r.task) WHERE r.repository=$1 AND r.name=$2 AND j.state NOT IN ('succeeded','failed','cancelled'))`, repo, name).Scan(&active); e != nil {
			return e
		}
		if active {
			return deferRun("previous_run_active", false)
		}
		for _, queue := range []string{"maintenance", "events"} {
			p, e := queuePolicy(ctx, tx, i.Tenant, queue)
			if e != nil {
				return e
			}
			if e = queueRoom(ctx, tx, p, 1); errors.Is(e, ErrQueueFull) {
				return deferRun(queue+"_queue_full", false)
			} else if e != nil {
				return e
			}
		}
		plan, e := retentionPreview(ctx, tx, requester, repo, name, RetentionRequest{ExpectedRevision: policy.Revision, Reason: current.Reason}, current.MaxTargets)
		if errors.Is(e, ErrRetentionBudget) {
			return deferRun("plan_budget_exceeded", false)
		}
		if e != nil {
			return e
		}
		if plan.EvaluatedAt.Before(current.NextDueAt) {
			return ErrNotFound
		}
		var next time.Time
		var missed int64
		if e = tx.QueryRow(ctx, `WITH slots AS(SELECT floor(extract(epoch FROM($1::timestamptz-$2::timestamptz))/$3::bigint)::bigint missed) SELECT missed,$2::timestamptz+((missed+1)*$3::bigint)*interval '1 second' FROM slots`, plan.EvaluatedAt, current.NextDueAt, current.IntervalSeconds).Scan(&missed, &next); e != nil {
			return e
		}
		plan.Schedule = &RetentionScheduleReceipt{Revision: current.Revision, DueAt: current.NextDueAt, CoalescedIntervals: missed}
		plan.Digest = ""
		raw, e := json.Marshal(plan)
		if e != nil {
			return e
		}
		plan.Digest = crypt.Digest(raw)
		task := "retention-" + crypt.Digest([]byte(repo+"\x00"+name+"\x00"+strconv.FormatInt(current.Revision, 10)+"\x00"+current.NextDueAt.UTC().Format(time.RFC3339Nano)))
		value, e := admitRetention(ctx, tx, requester, plan, task)
		if e != nil {
			return e
		}
		seq, parsedTask, e := ParseJobID(value["job"].(string))
		if e != nil {
			return e
		}
		sequence := Job{Sequence: seq, Task: parsedTask}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_schedule_runs(tenant,repository,name,revision,due_at,admitted_at,coalesced_intervals,sequence,task)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, i.Tenant, repo, name, current.Revision, current.NextDueAt, plan.EvaluatedAt, missed, sequence.Sequence, sequence.Task); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.retention_schedules SET next_due_at=$3,retry_at=$3,last_error='',blocked=false,last_sequence=$4,last_task=$5 WHERE repository=$1 AND name=$2`, repo, name, next, sequence.Sequence, sequence.Task); e != nil {
			return e
		}
		out = RetentionScheduleDispatch{Repository: repo, Policy: name, State: "admitted", Job: sequence.ID()}
		if e = appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "repository.retention.schedule.admitted", map[string]any{"repository": repo, "policy": name, "schedule_revision": current.Revision, "run": value, "next_due_at": next}, true); e != nil {
			return e
		}
		return retentionRequester(ctx, tx, requester)
	})
	return out, e
}

// verifyRetentionScheduleReceipt prevents either mutable job progress or a
// missing/contradictory scheduling marker from replacing admitted authority.
func verifyRetentionScheduleReceipt(ctx context.Context, tx pgx.Tx, j Job, p RetentionPlan, requester Identity) error {
	var repo, name string
	var revision, missed int64
	var due, admitted time.Time
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT r.repository,r.name,r.revision,r.due_at,r.admitted_at,r.coalesced_intervals,c.configuration FROM cratectl.retention_schedule_runs r JOIN cratectl.retention_schedule_revisions c ON(c.tenant,c.repository,c.name,c.revision)=(r.tenant,r.repository,r.name,r.revision) WHERE r.sequence=$1 AND r.task=$2`, j.Sequence, j.Task).Scan(&repo, &name, &revision, &due, &admitted, &missed, &raw)
	if errors.Is(e, pgx.ErrNoRows) {
		if p.Schedule != nil {
			return ErrRetentionInput
		}
		return nil
	}
	if e != nil {
		return e
	}
	var configuration RetentionSchedule
	marker := p.Schedule
	if repo != p.Policy.Repository || name != p.Policy.Name || marker == nil || len(raw) > 16384 || json.Unmarshal(raw, &configuration) != nil || configuration.AuthorizedActor != requester.Actor || !configuration.valid(repo, name) || !configuration.Enabled || configuration.Revision != revision || marker.Revision != revision || !marker.DueAt.Equal(due) || marker.CoalescedIntervals != missed || missed < 0 || !admitted.Equal(p.EvaluatedAt) || admitted.Before(due) || configuration.Policy.Revision != p.Policy.Revision || configuration.Policy.RetentionSettings != p.Policy.RetentionSettings || configuration.Policy.Actor != p.Policy.Actor || !configuration.Policy.ConfiguredAt.Equal(p.Policy.ConfiguredAt) || configuration.SourceRevision != p.SourceRevision || configuration.Reason != p.Reason || p.Targets > configuration.MaxTargets {
		return ErrRetentionInput
	}
	return nil
}
func retentionScheduleCurrent(ctx context.Context, tx pgx.Tx, i Identity, p RetentionPlan) error {
	if p.Schedule == nil {
		return nil
	}
	current, hash, e := retentionSchedule(ctx, tx, p.Policy.Repository, p.Policy.Name)
	if errors.Is(e, ErrNotFound) {
		return ErrRetentionScheduleChanged
	}
	if e != nil {
		return e
	}
	if current.Revision != p.Schedule.Revision || !current.Enabled || current.Policy.Revision != p.Policy.Revision || current.SourceRevision != p.SourceRevision || current.AuthorizedActor != i.Actor || hash != i.CredentialHash {
		return ErrRetentionScheduleChanged
	}
	return nil
}
