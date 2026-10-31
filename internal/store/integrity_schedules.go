// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrScheduleInput = errors.New("invalid integrity schedule")
var ErrScheduleRevision = errors.New("integrity schedule revision changed")
var ErrScheduleAuthorization = errors.New("schedule requester authorization changed during admission")
var ErrScheduleEvidence = errors.New("schedule progress disagrees with immutable admission evidence")

type ScheduleSettings struct {
	Repository      string `json:"repository"`
	IntervalSeconds int64  `json:"interval_seconds"`
	SampleSize      int    `json:"sample_size"`
	Enabled         bool   `json:"enabled"`
	Reason          string `json:"reason"`
}
type ScheduleRequest struct {
	ScheduleSettings
	ExpectedRevision int64 `json:"expected_revision"`
	RunImmediately   bool  `json:"run_immediately"`
	DryRun           bool  `json:"dry_run"`
}

func (r ScheduleRequest) Validate() error {
	if r.ExpectedRevision < 0 || r.ExpectedRevision == math.MaxInt64 || r.IntervalSeconds < 60 || r.IntervalSeconds > 31536000 || r.SampleSize < 1 || r.SampleSize > 1000000 || r.Repository != "" && !Name.MatchString(r.Repository) || !validLifecycleReason(r.Reason) || !utf8.ValidString(r.Reason) || strings.TrimSpace(r.Reason) == "" || !r.Enabled && r.RunImmediately {
		return ErrScheduleInput
	}
	return nil
}

type SampleCursor struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
}

func (c SampleCursor) valid() bool {
	return c == (SampleCursor{}) || Name.MatchString(c.Repository) && len(c.Digest) == 64 && strings.Trim(c.Digest, "0123456789abcdef") == "" && c.Size >= 0 && c.Size < 1<<62
}

type IntegritySchedule struct {
	ScheduleSettings
	Name            string       `json:"name"`
	Revision        int64        `json:"revision"`
	AuthorizedActor string       `json:"authorized_actor"`
	ConfiguredAt    time.Time    `json:"configured_at"`
	NextDueAt       time.Time    `json:"next_due_at"`
	RetryAt         time.Time    `json:"retry_at"`
	Blocked         bool         `json:"blocked"`
	LastError       string       `json:"last_error"`
	Cursor          SampleCursor `json:"cursor"`
	LastJob         string       `json:"last_job,omitempty"`
	LastState       string       `json:"last_state,omitempty"`
	lastSequence    int64
	lastTask        string
}

const scheduleColumns = `s.name,s.revision,s.repository,s.interval_seconds,s.sample_size,s.enabled,s.reason,s.requester_actor,s.configured_at,s.next_due_at,s.retry_at,s.blocked,s.last_error,s.cursor_repository,s.cursor_digest,s.cursor_size,COALESCE(s.last_sequence,0),COALESCE(s.last_task,''),COALESCE(j.state,'')`
const scheduleFrom = ` FROM cratectl.integrity_schedules s LEFT JOIN cratectl.jobs j ON (j.tenant,j.sequence,j.task)=(s.tenant,s.last_sequence,s.last_task) `

func scanSchedule(row pgx.Row, s *IntegritySchedule, hash *string) error {
	args := []any{&s.Name, &s.Revision, &s.Repository, &s.IntervalSeconds, &s.SampleSize, &s.Enabled, &s.Reason, &s.AuthorizedActor, &s.ConfiguredAt, &s.NextDueAt, &s.RetryAt, &s.Blocked, &s.LastError, &s.Cursor.Repository, &s.Cursor.Digest, &s.Cursor.Size, &s.lastSequence, &s.lastTask, &s.LastState}
	if hash != nil {
		args = append(args, hash)
	}
	e := row.Scan(args...)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	if !s.Cursor.valid() {
		return ErrScheduleInput
	}
	if s.lastSequence > 0 {
		s.LastJob = (Job{Sequence: s.lastSequence, Task: s.lastTask}).ID()
	}
	return nil
}
func readSchedule(ctx context.Context, tx pgx.Tx, name string) (IntegritySchedule, string, error) {
	var s IntegritySchedule
	var hash string
	e := scanSchedule(tx.QueryRow(ctx, `SELECT `+scheduleColumns+`,s.requester_hash`+scheduleFrom+`WHERE s.name=$1`, name), &s, &hash)
	return s, hash, e
}
func (s *Store) IntegritySchedule(ctx context.Context, i Identity, name string) (IntegritySchedule, error) {
	var out IntegritySchedule
	if i.Role != "admin" {
		return out, ErrDenied
	}
	if !Name.MatchString(name) {
		return out, ErrScheduleInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; out, _, e = readSchedule(ctx, tx, name); return e })
	return out, e
}
func (s *Store) IntegritySchedules(ctx context.Context, i Identity, after string, limit int) ([]IntegritySchedule, bool, error) {
	out := []IntegritySchedule{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if after != "" && !Name.MatchString(after) || limit < 1 || limit > 100 {
		return out, false, ErrScheduleInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+scheduleColumns+scheduleFrom+`WHERE s.name>$1 ORDER BY s.name LIMIT $2`, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v IntegritySchedule
			if e = scanSchedule(rows, &v, nil); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
func proposedSchedule(ctx context.Context, tx pgx.Tx, i Identity, name string, r ScheduleRequest) (IntegritySchedule, error) {
	old, _, e := readSchedule(ctx, tx, name)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return old, e
	}
	if old.Revision != r.ExpectedRevision {
		return old, ErrScheduleRevision
	}
	if r.Repository != "" {
		repo, e := repositoryRecordInTx(ctx, tx, i, r.Repository, "read")
		if e != nil {
			return old, e
		}
		if repo.Mode == "group" {
			return old, ErrScheduleInput
		}
	}
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return old, e
	}
	if old.Repository != r.Repository {
		old.Cursor = SampleCursor{}
	}
	out := old
	out.Name = name
	out.Revision++
	out.ScheduleSettings = r.ScheduleSettings
	out.AuthorizedActor = i.Actor
	out.ConfiguredAt = now
	out.Blocked = false
	out.LastError = ""
	out.RetryAt = now
	out.NextDueAt = now.Add(time.Duration(r.IntervalSeconds) * time.Second)
	if r.RunImmediately {
		out.NextDueAt = now
	}
	return out, nil
}
func (s *Store) SetIntegritySchedule(ctx context.Context, i Identity, name, key, fp string, r ScheduleRequest, budget int) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if !Name.MatchString(name) || r.Validate() != nil || r.SampleSize > budget || i.CredentialHash == "" {
		return Result{}, ErrScheduleInput
	}
	if r.DryRun {
		var out IntegritySchedule
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; out, e = proposedSchedule(ctx, tx, i, name, r); return e })
		return jsonResult(out, 200, e)
	}
	return s.mutateIntent(ctx, i, key, fp, "storage.schedule.configured", true, func(tx pgx.Tx) (any, int, error) {
		out, e := proposedSchedule(ctx, tx, i, name, r)
		if e != nil {
			return nil, 0, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.integrity_schedules(tenant,name,revision,repository,interval_seconds,sample_size,enabled,reason,requester_actor,requester_hash,configured_at,next_due_at,retry_at,cursor_repository,cursor_digest,cursor_size) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$11,$13,$14,$15) ON CONFLICT(tenant,name) DO UPDATE SET revision=EXCLUDED.revision,repository=EXCLUDED.repository,interval_seconds=EXCLUDED.interval_seconds,sample_size=EXCLUDED.sample_size,enabled=EXCLUDED.enabled,reason=EXCLUDED.reason,requester_actor=EXCLUDED.requester_actor,requester_hash=EXCLUDED.requester_hash,configured_at=EXCLUDED.configured_at,next_due_at=EXCLUDED.next_due_at,retry_at=EXCLUDED.retry_at,blocked=false,last_error='',cursor_repository=EXCLUDED.cursor_repository,cursor_digest=EXCLUDED.cursor_digest,cursor_size=EXCLUDED.cursor_size`, i.Tenant, name, out.Revision, out.Repository, out.IntervalSeconds, out.SampleSize, out.Enabled, out.Reason, i.Actor, i.CredentialHash, out.ConfiguredAt, out.NextDueAt, out.Cursor.Repository, out.Cursor.Digest, out.Cursor.Size)
		if e != nil {
			return nil, 0, e
		}
		raw, e := json.Marshal(out)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.integrity_schedule_revisions(tenant,name,revision,configuration) VALUES($1,$2,$3,$4)`, i.Tenant, name, out.Revision, raw); e != nil {
			return nil, 0, e
		}
		status := 200
		if r.ExpectedRevision == 0 {
			status = 201
		}
		return out, status, nil
	})
}
func (s *Store) IntegrityScheduleHistory(ctx context.Context, i Identity, name string, after int64, limit int) ([]json.RawMessage, bool, error) {
	out := []json.RawMessage{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if !Name.MatchString(name) || after < 0 || limit < 1 || limit > 100 {
		return out, false, ErrScheduleInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, _, e := readSchedule(ctx, tx, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT configuration FROM cratectl.integrity_schedule_revisions WHERE name=$1 AND revision>$2 ORDER BY revision LIMIT $3`, name, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw json.RawMessage
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if len(raw) > 16384 {
				return ErrMetadataLimit
			}
			out = append(out, raw)
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}

type SweepSampling struct {
	Schedule           string       `json:"schedule"`
	Revision           int64        `json:"revision"`
	DueAt              time.Time    `json:"due_at"`
	CoalescedIntervals int64        `json:"coalesced_intervals"`
	SampleSize         int          `json:"sample_size"`
	Before             SampleCursor `json:"cursor_before"`
	After              SampleCursor `json:"cursor_after"`
	Wrapped            bool         `json:"wrapped"`
}

func (p SweepSampling) valid() bool {
	return Name.MatchString(p.Schedule) && p.Revision > 0 && !p.DueAt.IsZero() && p.CoalescedIntervals >= 0 && p.SampleSize >= 1 && p.SampleSize <= 1000000 && p.Before.valid() && p.After.valid()
}

func samplingMatchesReceipt(p *SweepSampling, name string, revision int64, due time.Time, missed int64) bool {
	return p != nil && p.Schedule == name && p.Revision == revision && p.DueAt.Equal(due) && p.CoalescedIntervals == missed
}
func verifySweepReceipt(ctx context.Context, tx pgx.Tx, j Job, p SweepProgress) error {
	var name string
	var revision, missed int64
	var due time.Time
	e := tx.QueryRow(ctx, `SELECT name,revision,due_at,coalesced_intervals FROM cratectl.integrity_schedule_runs WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&name, &revision, &due, &missed)
	if errors.Is(e, pgx.ErrNoRows) {
		if p.Sampling != nil {
			return ErrScheduleEvidence
		}
		return nil
	}
	if e != nil {
		return e
	}
	if !samplingMatchesReceipt(p.Sampling, name, revision, due, missed) {
		return ErrScheduleEvidence
	}
	return nil
}

type ScheduleRun struct {
	SweepSampling
	AdmittedAt               time.Time     `json:"admitted_at"`
	Job                      string        `json:"job"`
	State                    string        `json:"state"`
	Progress                 SweepProgress `json:"progress"`
	SampleAssessed           bool          `json:"sample_assessed"`
	SampleClean              bool          `json:"sample_clean"`
	SecurityApproval         bool          `json:"security_approval"`
	AllTenantContentAssessed bool          `json:"all_tenant_content_assessed"`
}

func (s *Store) IntegrityScheduleRuns(ctx context.Context, i Identity, name string, after int64, limit int) ([]ScheduleRun, bool, error) {
	out := []ScheduleRun{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if !Name.MatchString(name) || after < 0 || limit < 1 || limit > 100 {
		return out, false, ErrScheduleInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, _, e := readSchedule(ctx, tx, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT r.admitted_at,r.sequence,r.task,r.revision,r.due_at,r.coalesced_intervals,j.state,j.payload FROM cratectl.integrity_schedule_runs r JOIN cratectl.jobs j ON(j.tenant,j.sequence,j.task)=(r.tenant,r.sequence,r.task) WHERE r.name=$1 AND r.sequence>$2 ORDER BY r.sequence LIMIT $3`, name, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var run ScheduleRun
			var seq int64
			var task string
			var raw []byte
			var revision, missed int64
			var due time.Time
			if e = rows.Scan(&run.AdmittedAt, &seq, &task, &revision, &due, &missed, &run.State, &raw); e != nil {
				return e
			}
			run.Job = (Job{Sequence: seq, Task: task}).ID()
			run.Progress, e = sweepProgress(raw)
			if e != nil {
				return ErrScheduleEvidence
			}
			if !samplingMatchesReceipt(run.Progress.Sampling, name, revision, due, missed) {
				return ErrScheduleEvidence
			}
			run.SweepSampling = *run.Progress.Sampling
			run.SampleAssessed = run.State == "succeeded" && run.Progress.Checked == run.Progress.Targets
			run.SampleClean = run.SampleAssessed && run.Progress.Targets > 0 && run.Progress.Issues == 0
			out = append(out, run)
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}

type ScheduleDispatch struct {
	Name  string `json:"name"`
	Job   string `json:"job,omitempty"`
	State string `json:"state"`
}

func deferSchedule(ctx context.Context, tx pgx.Tx, i WorkerIdentity, s IntegritySchedule, code string, blocked bool) (ScheduleDispatch, error) {
	out := ScheduleDispatch{Name: s.Name, State: code}
	_, e := tx.Exec(ctx, `UPDATE cratectl.integrity_schedules SET blocked=$2,last_error=$3,retry_at=clock_timestamp()+interval '30 seconds' WHERE name=$1`, s.Name, blocked, code)
	if e != nil {
		return out, e
	}
	if s.LastError != code || s.Blocked != blocked {
		e = appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "storage.schedule.deferred", map[string]any{"schedule": s.Name, "revision": s.Revision, "due_at": s.NextDueAt, "reason": code, "blocked": blocked}, false)
	}
	return out, e
}
func (s *Store) DispatchIntegritySchedule(ctx context.Context, i WorkerIdentity) (ScheduleDispatch, error) {
	var out ScheduleDispatch
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		var name string
		e := tx.QueryRow(ctx, `SELECT name FROM cratectl.integrity_schedules WHERE enabled AND NOT blocked AND next_due_at<=clock_timestamp() AND retry_at<=clock_timestamp() ORDER BY next_due_at,name LIMIT 1`).Scan(&name)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		current, hash, e := readSchedule(ctx, tx, name)
		if e != nil {
			return e
		}
		requester := Identity{Tenant: i.Tenant, Actor: current.AuthorizedActor, Role: "admin", CredentialHash: hash}
		if hash == "" {
			return ErrScheduleInput
		}
		if e = checkIdentity(ctx, tx, requester); errors.Is(e, ErrUnauthenticated) {
			out, e = deferSchedule(ctx, tx, i, current, "requester_authorization_unavailable", true)
			return e
		} else if e != nil {
			return e
		}
		if current.Repository != "" {
			r, e := repositoryRecordInTx(ctx, tx, requester, current.Repository, "read")
			if errors.Is(e, ErrNotFound) || errors.Is(e, ErrDenied) || errors.Is(e, ErrRepositorySuspended) || errors.Is(e, ErrRepositoryRemoved) {
				out, e = deferSchedule(ctx, tx, i, current, "repository_unavailable", false)
				return e
			}
			if e != nil {
				return e
			}
			if r.Mode == "group" {
				return ErrScheduleInput
			}
		}
		if current.LastJob != "" && current.LastState != "succeeded" && current.LastState != "failed" && current.LastState != "cancelled" {
			out, e = deferSchedule(ctx, tx, i, current, "previous_run_active", false)
			return e
		}
		policy, e := queuePolicy(ctx, tx, i.Tenant, "integrity")
		if e != nil {
			return e
		}
		if e = queueRoom(ctx, tx, policy, 1); errors.Is(e, ErrQueueFull) {
			out, e = deferSchedule(ctx, tx, i, current, "integrity_queue_full", false)
			return e
		} else if e != nil {
			return e
		}
		var now, next time.Time
		var missed int64
		if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return e
		}
		if e = tx.QueryRow(ctx, `WITH slots AS(SELECT floor(extract(epoch FROM($1::timestamptz-$2::timestamptz))/$3::bigint)::bigint AS missed) SELECT missed,$2::timestamptz+((missed+1)*$3::bigint)*interval '1 second' FROM slots`, now, current.NextDueAt, current.IntervalSeconds).Scan(&missed, &next); e != nil {
			return e
		}
		seq, e := nextEventSequence(ctx, tx, requester)
		if e != nil {
			return e
		}
		token, e := crypt.Token()
		if e != nil {
			return e
		}
		task := "sweep-" + crypt.Digest([]byte(token))
		progress, e := sampleBindings(ctx, tx, i.Tenant, seq, task, current, missed)
		if e != nil {
			return e
		}
		if e = checkScheduleRequester(ctx, tx, requester); e != nil {
			return e
		}
		raw, e := json.Marshal(progress)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload) VALUES($1,$2,$3,'integrity','storage.sweep',$4)`, i.Tenant, seq, task, raw); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.integrity_schedule_runs(tenant,name,revision,due_at,admitted_at,sequence,task,coalesced_intervals) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, i.Tenant, name, current.Revision, current.NextDueAt, now, seq, task, missed); e != nil {
			return e
		}
		cursor := progress.Sampling.After
		if _, e = tx.Exec(ctx, `UPDATE cratectl.integrity_schedules SET next_due_at=$2,retry_at=$2,last_error='',blocked=false,cursor_repository=$3,cursor_digest=$4,cursor_size=$5,last_sequence=$6,last_task=$7 WHERE name=$1`, name, next, cursor.Repository, cursor.Digest, cursor.Size, seq, task); e != nil {
			return e
		}
		out = ScheduleDispatch{Name: name, Job: (Job{Sequence: seq, Task: task}).ID(), State: "admitted"}
		if e = appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "storage.schedule.admitted", map[string]any{"schedule": name, "revision": current.Revision, "job": out.Job, "progress": progress, "next_due_at": next, "security_approval": false}, false); e != nil {
			return e
		}
		// Expiry can cross during any final write, including the journal/outbox.
		// Roll the complete admission back before workerTx attempts its commit.
		return checkScheduleRequester(ctx, tx, requester)
	})
	return out, e
}
func checkScheduleRequester(ctx context.Context, tx pgx.Tx, i Identity) error {
	e := checkIdentity(ctx, tx, i)
	if errors.Is(e, ErrUnauthenticated) {
		return ErrScheduleAuthorization
	}
	return e
}
func sampleBindings(ctx context.Context, tx pgx.Tx, tenant string, seq int64, task string, s IntegritySchedule, missed int64) (SweepProgress, error) {
	// Grouping and conflict detection include every retained binding. SQL result
	// count and the captured set are bounded; statement deadlines also apply.
	query := `WITH bindings AS (
 SELECT repository,digest,size,path,1::bigint artifact_references,0::bigint upload_parts FROM cratectl.artifacts WHERE($1='' OR repository=$1)
 UNION ALL SELECT u.repository,p.digest,p.size,'oci-upload/'||u.id||'/'||p.offset_bytes::text,0::bigint,1::bigint FROM cratectl.upload_parts p JOIN cratectl.uploads u ON(u.tenant,u.id)=(p.tenant,p.upload_id) WHERE($1='' OR u.repository=$1)
), grouped AS(SELECT repository,digest,size,min(path) path,sum(artifact_references)::bigint artifact_references,sum(upload_parts)::bigint upload_parts FROM bindings GROUP BY repository,digest,size), conflicts AS(SELECT *,min(size) OVER(PARTITION BY digest)<>max(size) OVER(PARTITION BY digest) reference_conflict FROM grouped), chosen AS(SELECT *,((repository,digest,size)>($2,$3,$4)) later FROM conflicts ORDER BY later DESC,repository,digest,size LIMIT $5)
 INSERT INTO cratectl.sweep_items(tenant,sequence,task,ordinal,repository,digest,size,path,artifact_references,upload_parts,reference_conflict) SELECT $6,$7,$8,row_number() OVER(ORDER BY later DESC,repository,digest,size),repository,digest,size,path,artifact_references,upload_parts,reference_conflict FROM chosen`
	tag, e := tx.Exec(ctx, query, s.Repository, s.Cursor.Repository, s.Cursor.Digest, s.Cursor.Size, s.SampleSize, tenant, seq, task)
	if e != nil {
		return SweepProgress{}, e
	}
	p := SweepProgress{SweepRequest: SweepRequest{Repository: s.Repository}, Targets: tag.RowsAffected(), Pass: 1, Sampling: &SweepSampling{Schedule: s.Name, Revision: s.Revision, DueAt: s.NextDueAt, CoalescedIntervals: missed, SampleSize: s.SampleSize, Before: s.Cursor, After: s.Cursor}}
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp(),COALESCE(sum(artifact_references),0)::bigint,COALESCE(sum(upload_parts),0)::bigint,COALESCE(bool_or((repository,digest,size)<=($3,$4,$5)),false) FROM cratectl.sweep_items WHERE sequence=$1 AND task=$2`, seq, task, s.Cursor.Repository, s.Cursor.Digest, s.Cursor.Size).Scan(&p.Cutoff, &p.ArtifactReferences, &p.UploadParts, &p.Sampling.Wrapped); e != nil {
		return p, e
	}
	if p.Targets > 0 {
		e = tx.QueryRow(ctx, `SELECT repository,digest,size FROM cratectl.sweep_items WHERE sequence=$1 AND task=$2 ORDER BY ordinal DESC LIMIT 1`, seq, task).Scan(&p.Sampling.After.Repository, &p.Sampling.After.Digest, &p.Sampling.After.Size)
	}
	if e == nil {
		e = p.Validate()
	}
	return p, e
}
