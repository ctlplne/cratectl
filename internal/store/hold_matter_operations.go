// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type MatterSelector struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
}
type MatterTarget struct {
	Ordinal           int64  `json:"ordinal"`
	Repository        string `json:"repository"`
	Path              string `json:"path"`
	Digest            string `json:"digest"`
	Revision          int64  `json:"revision"`
	Status            string `json:"status"`
	EffectiveHeld     bool   `json:"effective_held"`
	LifecycleRevision int64  `json:"lifecycle_revision"`
}
type MatterPreviewRequest struct {
	Action    string           `json:"action"`
	Reason    string           `json:"reason"`
	HoldUntil *time.Time       `json:"hold_until,omitempty"`
	Targets   []MatterSelector `json:"targets"`
}
type MatterPlan struct {
	Matter      HoldMatter     `json:"matter"`
	Action      string         `json:"action"`
	Reason      string         `json:"reason"`
	HoldUntil   *time.Time     `json:"hold_until,omitempty"`
	Requester   string         `json:"requester"`
	EvaluatedAt time.Time      `json:"evaluated_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	TargetCount int            `json:"target_count"`
	Targets     []MatterTarget `json:"targets,omitempty"`
	Digest      string         `json:"preview_digest"`
}
type MatterOperation struct {
	Sequence       int64      `json:"sequence"`
	Matter         string     `json:"matter"`
	Revision       int64      `json:"revision"`
	State          string     `json:"state"`
	Plan           MatterPlan `json:"plan"`
	Requester      string     `json:"requester"`
	Approver       string     `json:"approver,omitempty"`
	ApprovalReason string     `json:"approval_reason,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Job            string     `json:"job,omitempty"`
	ChangeSequence int64      `json:"change_sequence"`
	CreatedAt      time.Time  `json:"created_at"`
	ChangedAt      time.Time  `json:"changed_at"`
}
type matterOperationRecord struct {
	MatterOperation
	requester, approver Identity
	jobSequence         *int64
	jobTask             *string
}
type MatterApprovalRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Digest           string `json:"preview_digest"`
	Reason           string `json:"reason"`
}

func matterPreview(ctx context.Context, tx pgx.Tx, i Identity, name string, r MatterPreviewRequest, evaluated *time.Time, budget, byteBudget int) (MatterPlan, error) {
	p := MatterPlan{Action: r.Action, Reason: r.Reason, HoldUntil: r.HoldUntil, Requester: i.Actor, Targets: []MatterTarget{}}
	if e := matterAdmin(i, name); e != nil {
		return p, e
	}
	if budget < 1 || budget > 10000 || byteBudget < 1024 || byteBudget > 64<<20 || len(r.Targets) < 1 || len(r.Targets) > budget || !matterReason(r.Reason) || (r.Action != "hold" && r.Action != "release_hold") || r.Action == "release_hold" && r.HoldUntil != nil {
		return p, ErrMatterInput
	}
	var e error
	p.Matter, e = matterInTx(ctx, tx, name)
	if e != nil {
		return p, e
	}
	if p.Matter.State != "open" {
		return p, ErrMatterChanged
	}
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return p, e
	}
	p.EvaluatedAt = now.UTC()
	if evaluated != nil {
		p.EvaluatedAt = evaluated.UTC()
	}
	p.ExpiresAt = p.EvaluatedAt.Add(15 * time.Minute)
	if p.EvaluatedAt.After(now) || !p.ExpiresAt.After(now) {
		return p, ErrMatterChanged
	}
	if p.HoldUntil != nil {
		v := p.HoldUntil.UTC().Truncate(time.Microsecond)
		p.HoldUntil = &v
		if !v.After(now) {
			return p, ErrMatterChanged
		}
	}
	selectors := slices.Clone(r.Targets)
	slices.SortFunc(selectors, func(a, b MatterSelector) int {
		return strings.Compare(a.Repository+"\n"+a.Path, b.Repository+"\n"+b.Path)
	})
	used := 0
	last := ""
	for n, target := range selectors {
		key := target.Repository + "\n" + target.Path
		if key == last {
			return p, ErrMatterInput
		}
		last = key
		a, e := holdReferenceInTx(ctx, tx, i, target.Repository, target.Path)
		if e != nil {
			return p, e
		}
		member, e := matterMemberInTx(ctx, tx, name, target.Repository, target.Path)
		if e != nil {
			return p, e
		}
		if member.Revision == math.MaxInt64 || member.Revision > 0 && member.Digest != a.Digest {
			return p, ErrMatterChanged
		}
		if r.Action == "release_hold" && member.Revision == 0 {
			return p, ErrMatterChanged
		}
		state, e := artifactStateInTx(ctx, tx, target.Repository, target.Path)
		if e != nil {
			return p, e
		}
		status := "new"
		if member.Revision > 0 {
			status = "expired"
			if member.Released {
				status = "released"
			} else if member.Held {
				status = "active"
			}
		}
		item := MatterTarget{Ordinal: int64(n + 1), Repository: a.Repository, Path: a.Path, Digest: a.Digest, Revision: member.Revision, Status: status, EffectiveHeld: state.Held, LifecycleRevision: state.Revision}
		raw, _ := json.Marshal(item)
		used += len(raw)
		if used > byteBudget {
			return p, ErrMatterBudget
		}
		p.Targets = append(p.Targets, item)
	}
	p.TargetCount = len(p.Targets)
	raw, e := json.Marshal(p)
	if e != nil {
		return p, e
	}
	if len(raw) > byteBudget {
		return p, ErrMatterBudget
	}
	p.Digest = crypt.Digest(append([]byte(i.Tenant+"\x00"+i.Actor+"\x00"+i.CredentialHash+"\x00"), raw...))
	// raw includes an empty preview_digest string. Account for the digest bytes
	// too: callers receive and review the complete response within this budget.
	if len(raw)+len(p.Digest) > byteBudget {
		return p, ErrMatterBudget
	}
	return p, nil
}
func (s *Store) PreviewMatterOperation(ctx context.Context, i Identity, name string, r MatterPreviewRequest, budget, bytes int) (MatterPlan, error) {
	var p MatterPlan
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var e error
		p, e = matterPreview(ctx, tx, i, name, r, nil, budget, bytes)
		return e
	})
	return p, e
}
func operationRecord(ctx context.Context, tx pgx.Tx, tenant, name string, sequence int64) (matterOperationRecord, error) {
	var o matterOperationRecord
	o.requester = Identity{Tenant: tenant, Role: "admin"}
	o.approver = Identity{Tenant: tenant, Role: "admin"}
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT sequence,matter,revision,state,plan,requester_actor,requester_hash,approver_actor,approver_hash,approval_reason,expires_at,job_sequence,job_task,change_sequence,created_at,changed_at FROM cratectl.hold_matter_operations WHERE sequence=$1 AND matter=$2`, sequence, name).Scan(&o.Sequence, &o.Matter, &o.Revision, &o.State, &raw, &o.requester.Actor, &o.requester.CredentialHash, &o.approver.Actor, &o.approver.CredentialHash, &o.ApprovalReason, &o.ExpiresAt, &o.jobSequence, &o.jobTask, &o.ChangeSequence, &o.CreatedAt, &o.ChangedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return o, ErrNotFound
	}
	if e != nil {
		return o, e
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &o.Plan) != nil || o.Plan.Matter.Name != name || o.Plan.TargetCount < 1 || o.Plan.TargetCount > 10000 || len(o.Plan.Targets) != 0 || !uploadDigest.MatchString(o.Plan.Digest) || o.requester.CredentialHash == "" {
		return o, ErrMatterInput
	}
	o.Requester = o.requester.Actor
	o.Approver = o.approver.Actor
	if o.jobSequence != nil && o.jobTask != nil {
		o.Job = (Job{Sequence: *o.jobSequence, Task: *o.jobTask}).ID()
	}
	return o, nil
}
func matterIdentity(ctx context.Context, tx pgx.Tx, i Identity) error {
	if i.CredentialHash == "" || i.Role != "admin" {
		return ErrMatterAuthorization
	}
	e := checkIdentity(ctx, tx, i)
	if errors.Is(e, ErrUnauthenticated) || errors.Is(e, ErrDenied) {
		return ErrMatterAuthorization
	}
	return e
}
func matterCurrent(ctx context.Context, tx pgx.Tx, o matterOperationRecord) error {
	if e := matterIdentity(ctx, tx, o.requester); e != nil {
		return e
	}
	if o.Plan.Action == "release_hold" {
		if o.approver.Actor == "" || o.approver.Actor == o.requester.Actor {
			return ErrMatterAuthorization
		}
		if e := matterIdentity(ctx, tx, o.approver); e != nil {
			return e
		}
	}
	m, e := matterInTx(ctx, tx, o.Matter)
	if e != nil {
		return e
	}
	if m.Revision != o.Plan.Matter.Revision || m.State != "open" {
		return ErrMatterChanged
	}
	var live bool
	e = tx.QueryRow(ctx, `SELECT clock_timestamp()<$1 AND ($2::timestamptz IS NULL OR clock_timestamp()<$2)`, o.ExpiresAt, o.Plan.HoldUntil).Scan(&live)
	if e != nil {
		return e
	}
	if !live {
		return ErrMatterChanged
	}
	return nil
}
func enqueueMatterOperation(ctx context.Context, tx pgx.Tx, i Identity, o *matterOperationRecord, sequence int64, task string) error {
	policy, e := queuePolicy(ctx, tx, i.Tenant, "maintenance")
	if e != nil {
		return e
	}
	if e = queueRoom(ctx, tx, policy, 1); e != nil {
		return e
	}
	raw, _ := json.Marshal(map[string]any{"matter": o.Matter, "operation": o.Sequence, "targets": o.Plan.TargetCount, "preview_digest": o.Plan.Digest})
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload)VALUES($1,$2,$3,'maintenance','hold.matter.operation',$4)`, i.Tenant, sequence, task, raw)
	if e != nil {
		return e
	}
	o.jobSequence = &sequence
	o.jobTask = &task
	o.Job = (Job{Sequence: sequence, Task: task}).ID()
	return nil
}
func (s *Store) StartMatterOperation(ctx context.Context, i Identity, name, key, fp string, p MatterPlan, budget, byteBudget int) (Result, error) {
	if e := matterAdmin(i, name); e != nil {
		return Result{}, e
	}
	if budget < 1 || budget > 10000 || byteBudget < 1024 || byteBudget > 64<<20 || p.TargetCount < 1 || p.TargetCount > budget || i.CredentialHash == "" || !uploadDigest.MatchString(p.Digest) || len(p.Targets) != p.TargetCount {
		return Result{}, ErrMatterInput
	}
	authorize := func(tx pgx.Tx) error { _, e := matterInTx(ctx, tx, name); return e }
	return s.mutateIntentChecked(ctx, i, key, fp, "hold.matter.operation.requested", true, authorize, func(tx pgx.Tx) (any, int, error) {
		selectors := make([]MatterSelector, len(p.Targets))
		for n, item := range p.Targets {
			selectors[n] = MatterSelector{item.Repository, item.Path}
		}
		expected, e := matterPreview(ctx, tx, i, name, MatterPreviewRequest{Action: p.Action, Reason: p.Reason, HoldUntil: p.HoldUntil, Targets: selectors}, &p.EvaluatedAt, budget, byteBudget)
		if e != nil {
			return nil, 0, e
		}
		left, _ := json.Marshal(p)
		right, _ := json.Marshal(expected)
		if !bytes.Equal(left, right) {
			return nil, 0, ErrMatterChanged
		}
		seq, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		summary := expected
		summary.Targets = nil
		raw, _ := json.Marshal(summary)
		o := matterOperationRecord{MatterOperation: MatterOperation{Sequence: seq, Matter: name, Revision: 1, State: "awaiting_approval", Plan: summary, Requester: i.Actor, ExpiresAt: expected.ExpiresAt, ChangeSequence: seq}, requester: i}
		if expected.Action == "hold" {
			o.State = "approved"
			task := "hold-" + crypt.Digest([]byte(i.Actor+"\x00"+key+"\x00"+fp))
			if e = enqueueMatterOperation(ctx, tx, i, &o, seq, task); e != nil {
				return nil, 0, e
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.hold_matter_operations(tenant,sequence,matter,state,plan,requester_actor,requester_hash,expires_at,job_sequence,job_task,change_sequence)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$2)`, i.Tenant, seq, name, o.State, raw, i.Actor, i.CredentialHash, o.ExpiresAt, o.jobSequence, o.jobTask)
		if e != nil {
			return nil, 0, e
		}
		for _, item := range expected.Targets {
			raw, _ := json.Marshal(item)
			if _, e = tx.Exec(ctx, `INSERT INTO cratectl.hold_matter_targets(tenant,operation,ordinal,target)VALUES($1,$2,$3,$4)`, i.Tenant, seq, item.Ordinal, raw); e != nil {
				return nil, 0, e
			}
		}
		o, e = operationRecord(ctx, tx, i.Tenant, name, seq)
		return map[string]any{"matter_name": name, "operation": o.MatterOperation, "retained_bytes": true}, 202, e
	})
}
func (s *Store) ReviewMatterOperation(ctx context.Context, i Identity, name string, sequence int64, action, key, fp string, r MatterApprovalRequest) (Result, error) {
	if e := matterAdmin(i, name); e != nil {
		return Result{}, e
	}
	if sequence < 1 || r.ExpectedRevision < 1 || r.ExpectedRevision == math.MaxInt64 || !matterReason(r.Reason) || !uploadDigest.MatchString(r.Digest) || (action != "approve" && action != "cancel") {
		return Result{}, ErrMatterInput
	}
	authorize := func(tx pgx.Tx) error {
		o, e := operationRecord(ctx, tx, i.Tenant, name, sequence)
		if e != nil {
			return e
		}
		if action == "approve" {
			if i.Actor == o.requester.Actor || o.Plan.Action != "release_hold" {
				return ErrDenied
			}
			if e = matterIdentity(ctx, tx, o.requester); e != nil {
				return e
			}
			if o.State == "approved" {
				return matterIdentity(ctx, tx, o.approver)
			}
		}
		return nil
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "hold.matter.operation."+action, true, authorize, func(tx pgx.Tx) (any, int, error) {
		o, e := operationRecord(ctx, tx, i.Tenant, name, sequence)
		if e != nil {
			return nil, 0, e
		}
		if o.Revision != r.ExpectedRevision || o.State != "awaiting_approval" || o.Plan.Digest != r.Digest {
			return nil, 0, ErrMatterChanged
		}
		seq, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		state := "cancelled"
		if action == "approve" {
			o.approver = i
			if e = matterCurrent(ctx, tx, o); e != nil {
				return nil, 0, e
			}
			state = "approved"
			task := "hold-" + crypt.Digest([]byte(i.Actor+"\x00"+key+"\x00"+fp))
			if e = enqueueMatterOperation(ctx, tx, i, &o, seq, task); e != nil {
				return nil, 0, e
			}
		}
		_, e = tx.Exec(ctx, `UPDATE cratectl.hold_matter_operations SET state=$1,revision=revision+1,approver_actor=$2,approver_hash=$3,approval_reason=$4,job_sequence=$5,job_task=$6,change_sequence=$7,changed_at=clock_timestamp() WHERE sequence=$8`, state, o.approver.Actor, o.approver.CredentialHash, r.Reason, o.jobSequence, o.jobTask, seq, sequence)
		if e != nil {
			return nil, 0, e
		}
		o, e = operationRecord(ctx, tx, i.Tenant, name, sequence)
		return map[string]any{"matter_name": name, "operation": o.MatterOperation, "retained_bytes": true}, 202, e
	})
}
