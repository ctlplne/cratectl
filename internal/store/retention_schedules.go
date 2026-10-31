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

	"github.com/jackc/pgx/v5"
)

var ErrRetentionScheduleChanged = errors.New("retention schedule changed or paused")

type RetentionScheduleSettings struct {
	IntervalSeconds int64  `json:"interval_seconds"`
	MaxTargets      int    `json:"max_targets"`
	Enabled         bool   `json:"enabled"`
	Reason          string `json:"reason"`
}

func (s RetentionScheduleSettings) Validate() error {
	if s.IntervalSeconds < 60 || s.IntervalSeconds > 31536000 || s.MaxTargets < 1 || s.MaxTargets > 10000 || !validLifecycleReason(s.Reason) || !utf8.ValidString(s.Reason) || strings.TrimSpace(s.Reason) == "" {
		return ErrRetentionInput
	}
	return nil
}

type RetentionScheduleRequest struct {
	RetentionScheduleSettings
	ExpectedRevision           int64 `json:"expected_revision"`
	ExpectedPolicyRevision     int64 `json:"expected_policy_revision"`
	ExpectedSourceRevision     int64 `json:"expected_source_revision"`
	AuthorizeFutureRetirements bool  `json:"authorize_future_retirements"`
	RunImmediately             bool  `json:"run_immediately"`
	DryRun                     bool  `json:"dry_run"`
}

func (r RetentionScheduleRequest) Validate() error {
	if r.RetentionScheduleSettings.Validate() != nil || r.ExpectedRevision < 0 || r.ExpectedRevision == math.MaxInt64 || r.ExpectedPolicyRevision < 1 || r.ExpectedSourceRevision < 0 || r.Enabled && !r.AuthorizeFutureRetirements || !r.Enabled && r.RunImmediately {
		return ErrRetentionInput
	}
	return nil
}

type RetentionSchedule struct {
	RetentionScheduleSettings
	Repository                 string          `json:"repository"`
	Policy                     RetentionPolicy `json:"policy"`
	SourceRevision             int64           `json:"source_revision"`
	Revision                   int64           `json:"revision"`
	AuthorizeFutureRetirements bool            `json:"authorize_future_retirements"`
	AuthorizedActor            string          `json:"authorized_actor"`
	ConfiguredAt               time.Time       `json:"configured_at"`
	NextDueAt                  time.Time       `json:"next_due_at"`
	RetryAt                    time.Time       `json:"retry_at"`
	Blocked                    bool            `json:"blocked"`
	LastError                  string          `json:"last_error"`
	LastJob                    string          `json:"last_job,omitempty"`
	LastState                  string          `json:"last_state,omitempty"`
	lastSequence               int64
	lastTask                   string
}

func (s RetentionSchedule) valid(repo, name string) bool {
	return s.RetentionScheduleSettings.Validate() == nil && s.Repository == repo && s.Policy.Repository == repo && s.Policy.Name == name && s.Policy.Revision > 0 && s.Policy.RetentionSettings.Validate() == nil && s.SourceRevision >= 0 && s.Revision > 0 && Name.MatchString(s.AuthorizedActor) && !s.ConfiguredAt.IsZero() && s.AuthorizeFutureRetirements == s.Enabled && (!s.Enabled || s.Policy.Enabled)
}
func retentionSchedule(ctx context.Context, tx pgx.Tx, repo, name string) (RetentionSchedule, string, error) {
	var out RetentionSchedule
	var raw []byte
	var hash string
	var revision, policyRevision, sourceRevision int64
	var enabled bool
	var configured, next, retry time.Time
	var blocked bool
	var code, state, task string
	var sequence int64
	e := tx.QueryRow(ctx, `SELECT s.configuration,s.requester_hash,s.revision,s.policy_revision,s.source_revision,s.enabled,s.configured_at,s.next_due_at,s.retry_at,s.blocked,s.last_error,COALESCE(s.last_sequence,0),COALESCE(s.last_task,''),COALESCE(j.state,'') FROM cratectl.retention_schedules s LEFT JOIN cratectl.jobs j ON(j.tenant,j.sequence,j.task)=(s.tenant,s.last_sequence,s.last_task) WHERE s.repository=$1 AND s.name=$2`, repo, name).Scan(&raw, &hash, &revision, &policyRevision, &sourceRevision, &enabled, &configured, &next, &retry, &blocked, &code, &sequence, &task, &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, hash, ErrNotFound
	}
	if e != nil {
		return out, hash, e
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &out) != nil || !out.valid(repo, name) || out.Revision != revision || out.Policy.Revision != policyRevision || out.SourceRevision != sourceRevision || out.Enabled != enabled || !out.ConfiguredAt.Equal(configured) || hash == "" {
		return out, hash, ErrRetentionInput
	}
	out.NextDueAt = next
	out.RetryAt = retry
	out.Blocked = blocked
	out.LastError = code
	out.LastState = state
	out.lastSequence = sequence
	out.lastTask = task
	out.LastJob = ""
	if sequence > 0 {
		out.LastJob = (Job{Sequence: sequence, Task: task}).ID()
	}
	return out, hash, nil
}
func retentionScheduleAccess(ctx context.Context, tx pgx.Tx, i Identity, repo, name string) error {
	if !Name.MatchString(repo) || !Name.MatchString(name) {
		return ErrRetentionInput
	}
	_, e := retentionRepositoryRecord(ctx, tx, i, repo)
	return e
}
func (s *Store) RetentionSchedule(ctx context.Context, i Identity, repo, name string) (RetentionSchedule, error) {
	var out RetentionSchedule
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if e := retentionScheduleAccess(ctx, tx, i, repo, name); e != nil {
			return e
		}
		var e error
		out, _, e = retentionSchedule(ctx, tx, repo, name)
		return e
	})
	return out, e
}
func proposedRetentionSchedule(ctx context.Context, tx pgx.Tx, i Identity, repo, name string, r RetentionScheduleRequest) (RetentionSchedule, error) {
	var out RetentionSchedule
	if e := retentionScheduleAccess(ctx, tx, i, repo, name); e != nil {
		return out, e
	}
	old, _, e := retentionSchedule(ctx, tx, repo, name)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return out, e
	}
	if old.Revision != r.ExpectedRevision {
		return out, ErrRetentionScheduleChanged
	}
	record, e := retentionRepositoryRecord(ctx, tx, i, repo)
	if e != nil {
		return out, e
	}
	if r.Enabled {
		record, e = retentionRepository(ctx, tx, i, repo)
		if e != nil {
			return out, e
		}
	}
	policy, e := retentionPolicy(ctx, tx, repo, name)
	if e != nil {
		return out, e
	}
	if policy.Revision != r.ExpectedPolicyRevision || record.SourceRevision != r.ExpectedSourceRevision || r.Enabled && !policy.Enabled {
		return out, ErrRetentionChanged
	}
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return out, e
	}
	out = old
	out.RetentionScheduleSettings = r.RetentionScheduleSettings
	out.Repository = repo
	out.Policy = policy
	out.SourceRevision = record.SourceRevision
	out.Revision = r.ExpectedRevision + 1
	out.AuthorizeFutureRetirements = r.Enabled
	out.AuthorizedActor = i.Actor
	out.ConfiguredAt = now
	out.NextDueAt = now.Add(time.Duration(r.IntervalSeconds) * time.Second)
	out.RetryAt = now
	out.Blocked = false
	out.LastError = ""
	if r.RunImmediately {
		out.NextDueAt = now
	}
	return out, nil
}
func (s *Store) SetRetentionSchedule(ctx context.Context, i Identity, repo, name, key, fp string, r RetentionScheduleRequest, budget int) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if r.Validate() != nil || i.CredentialHash == "" {
		return Result{}, ErrRetentionInput
	}
	prepare := func(tx pgx.Tx) (RetentionSchedule, error) {
		if r.MaxTargets > budget {
			return RetentionSchedule{}, ErrRetentionInput
		}
		return proposedRetentionSchedule(ctx, tx, i, repo, name, r)
	}
	if r.DryRun {
		var out RetentionSchedule
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			var e error
			out, e = prepare(tx)
			return e
		})
		return jsonResult(out, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "repository.retention.schedule.configured", true, func(tx pgx.Tx) error { return retentionScheduleAccess(ctx, tx, i, repo, name) }, func(tx pgx.Tx) (any, int, error) {
		out, e := prepare(tx)
		if e != nil {
			return nil, 0, e
		}
		raw, e := json.Marshal(out)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_schedules(tenant,repository,name,revision,policy_revision,source_revision,configuration,enabled,requester_hash,configured_at,next_due_at,retry_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10) ON CONFLICT(tenant,repository,name)DO UPDATE SET revision=excluded.revision,policy_revision=excluded.policy_revision,source_revision=excluded.source_revision,configuration=excluded.configuration,enabled=excluded.enabled,requester_hash=excluded.requester_hash,configured_at=excluded.configured_at,next_due_at=excluded.next_due_at,retry_at=excluded.retry_at,blocked=false,last_error=''`, i.Tenant, repo, name, out.Revision, out.Policy.Revision, out.SourceRevision, raw, out.Enabled, i.CredentialHash, out.ConfiguredAt, out.NextDueAt); e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_schedule_revisions(tenant,repository,name,revision,configuration)VALUES($1,$2,$3,$4,$5)`, i.Tenant, repo, name, out.Revision, raw); e != nil {
			return nil, 0, e
		}
		status := 200
		if r.ExpectedRevision == 0 {
			status = 201
		}
		return out, status, nil
	})
}
func (s *Store) RetentionScheduleHistory(ctx context.Context, i Identity, repo, name string, after int64, limit int) ([]json.RawMessage, bool, error) {
	out := []json.RawMessage{}
	if after < 0 || limit < 1 || limit > 100 {
		return out, false, ErrRetentionInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if e := retentionScheduleAccess(ctx, tx, i, repo, name); e != nil {
			return e
		}
		if _, _, e := retentionSchedule(ctx, tx, repo, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT configuration FROM cratectl.retention_schedule_revisions WHERE repository=$1 AND name=$2 AND revision>$3 ORDER BY revision LIMIT $4`, repo, name, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if len(raw) > 16384 {
				return ErrRetentionInput
			}
			out = append(out, json.RawMessage(raw))
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
func (s *Store) RetentionScheduleRuns(ctx context.Context, i Identity, repo, name string, after int64, limit int) ([]RetentionRunSummary, bool, error) {
	out := []RetentionRunSummary{}
	if after < 0 || limit < 1 || limit > 100 {
		return out, false, ErrRetentionInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if e := retentionScheduleAccess(ctx, tx, i, repo, name); e != nil {
			return e
		}
		if _, _, e := retentionSchedule(ctx, tx, repo, name); e != nil {
			return e
		}
		var e error
		out, e = retentionRunSummaries(ctx, tx, i, repo, name, after, limit, true)
		return e
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
