// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

func matterIntent(ctx context.Context, tx pgx.Tx, tenant string, j Job) (matterOperationRecord, error) {
	var empty matterOperationRecord
	if j.Kind != "hold.matter.operation" || j.Queue != "maintenance" {
		return empty, ErrMatterInput
	}
	var name string
	var sequence int64
	e := tx.QueryRow(ctx, `SELECT matter,sequence FROM cratectl.hold_matter_operations WHERE job_sequence=$1 AND job_task=$2`, j.Sequence, j.Task).Scan(&name, &sequence)
	if e != nil {
		return empty, e
	}
	o, e := operationRecord(ctx, tx, tenant, name, sequence)
	if e != nil {
		return o, e
	}
	if o.State != "approved" || o.Job != j.ID() || (o.Plan.Action != "hold" && o.Plan.Action != "release_hold") {
		return o, ErrMatterInput
	}
	var count, last int64
	e = tx.QueryRow(ctx, `SELECT count(*),COALESCE(max(ordinal),0) FROM cratectl.hold_matter_targets WHERE operation=$1`, o.Sequence).Scan(&count, &last)
	if e != nil {
		return o, e
	}
	if count != int64(o.Plan.TargetCount) || last != count {
		return o, ErrMatterInput
	}
	return o, nil
}
func matterTargetEffect(ctx context.Context, tx pgx.Tx, i WorkerIdentity, o matterOperationRecord, target MatterTarget, seq int64) (string, HoldMatterMember, ArtifactState, error) {
	var current ArtifactState
	var member HoldMatterMember
	if target.Ordinal < 1 || target.Ordinal > int64(o.Plan.TargetCount) || !Name.MatchString(target.Repository) || !validHoldPath(target.Path) || !uploadDigest.MatchString(target.Digest) || target.Revision < 0 || target.Revision == math.MaxInt64 {
		return "", member, current, ErrMatterInput
	}
	a, e := holdReferenceInTx(ctx, tx, o.requester, target.Repository, target.Path)
	if e != nil {
		return "", member, current, e
	}
	member, e = matterMemberInTx(ctx, tx, o.Matter, target.Repository, target.Path)
	if e != nil {
		return "", member, current, e
	}
	current, e = artifactStateInTx(ctx, tx, target.Repository, target.Path)
	if e != nil {
		return "", member, current, e
	}
	if a.Digest != target.Digest || member.Revision != target.Revision || member.Revision > 0 && member.Digest != target.Digest {
		return "changed", member, current, nil
	}
	if o.Plan.Action == "release_hold" && member.Released {
		return "already_released", member, current, nil
	}
	if o.Plan.Action == "release_hold" && member.Revision == 0 {
		return "changed", member, current, nil
	}
	created := member.CreatedSequence
	if created == 0 {
		created = seq
	}
	holdReason, until := member.HoldReason, member.HoldUntil
	outcome := "released"
	if o.Plan.Action == "hold" {
		holdReason = o.Plan.Reason
		until = o.Plan.HoldUntil
		outcome = "held"
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.hold_matter_members(tenant,matter,repository,path,digest,revision,released,hold_reason,hold_until,reason,actor,created_sequence,change_sequence)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
 ON CONFLICT(tenant,matter,repository,path) DO UPDATE SET revision=excluded.revision,released=excluded.released,hold_reason=excluded.hold_reason,hold_until=excluded.hold_until,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, o.Matter, target.Repository, target.Path, target.Digest, member.Revision+1, o.Plan.Action == "release_hold", holdReason, until, o.Plan.Reason, o.Requester, created, seq)
	if e != nil {
		return "", member, current, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,revision,reason,actor,change_sequence)VALUES($1,$2,$3,$4,1,$5,$6,$7) ON CONFLICT(tenant,repository,path) DO UPDATE SET revision=artifact_lifecycle.revision+1,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, target.Repository, target.Path, target.Digest, o.Plan.Reason, o.Requester, seq)
	if e != nil {
		return "", member, current, e
	}
	member, e = matterMemberInTx(ctx, tx, o.Matter, target.Repository, target.Path)
	if e != nil {
		return "", member, current, e
	}
	current, e = artifactStateInTx(ctx, tx, target.Repository, target.Path)
	return outcome, member, current, e
}

// One target and its receipt share the lease-fenced transaction. The immutable
// manifest and stored authorities, rather than jobs.payload, authorize effects.
func (s *Store) StepHoldMatter(ctx context.Context, i WorkerIdentity, j Job) (string, error) {
	outcome := ""
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		o, e := matterIntent(ctx, tx, i.Tenant, j)
		if e != nil {
			return e
		}
		var lease time.Time
		if e = tx.QueryRow(ctx, `SELECT lease_until FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&lease); e != nil {
			return e
		}
		outcome = "cancelled"
		if state != "cancel_requested" {
			if e = matterCurrent(ctx, tx, o); e != nil {
				return e
			}
			var raw []byte
			var ordinal int64
			e = tx.QueryRow(ctx, `SELECT t.ordinal,t.target FROM cratectl.hold_matter_targets t WHERE t.operation=$1 AND NOT EXISTS(SELECT 1 FROM cratectl.hold_matter_outcomes f WHERE (f.tenant,f.operation,f.ordinal)=(t.tenant,t.operation,t.ordinal)) ORDER BY t.ordinal LIMIT 1`, o.Sequence).Scan(&ordinal, &raw)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if e == nil {
				var target MatterTarget
				if len(raw) > 8192 || json.Unmarshal(raw, &target) != nil || target.Ordinal != ordinal {
					return ErrMatterInput
				}
				seq, e := nextEventSequence(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"})
				if e != nil {
					return e
				}
				status, member, current, e := matterTargetEffect(ctx, tx, i, o, target, seq)
				if e != nil {
					return e
				}
				_, e = tx.Exec(ctx, `INSERT INTO cratectl.hold_matter_outcomes(tenant,operation,ordinal,generation,outcome,member_revision,lifecycle_revision,effective_held,worker,event_sequence)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, i.Tenant, o.Sequence, ordinal, j.Generation, status, member.Revision, current.Revision, current.Held, i.Actor, seq)
				if e != nil {
					return e
				}
				if e = appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "hold.matter.target", map[string]any{"matter_name": o.Matter, "operation": o.Sequence, "job": j.ID(), "requester": o.Requester, "approver": o.Approver, "ordinal": ordinal, "outcome": status, "target": target, "member": member, "current": current, "retained_bytes": true}, true); e != nil {
					return e
				}
			}
			var remaining bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.hold_matter_targets t WHERE t.operation=$1 AND NOT EXISTS(SELECT 1 FROM cratectl.hold_matter_outcomes f WHERE(f.tenant,f.operation,f.ordinal)=(t.tenant,t.operation,t.ordinal)))`, o.Sequence).Scan(&remaining); e != nil {
				return e
			}
			outcome = "succeeded"
			if remaining {
				outcome = "pending"
			}
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET state=$1,cycle_attempts=0,lease_token='',lease_until='epoch',available_at=clock_timestamp(),updated_at=clock_timestamp(),finished_at=CASE WHEN $1='pending' THEN NULL ELSE clock_timestamp() END,last_error='' WHERE sequence=$2 AND task=$3 AND generation=$4 AND lease_token=$5 AND lease_until>clock_timestamp()`, outcome, j.Sequence, j.Task, j.Generation, j.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrJobLeaseLost
		}
		j.State = outcome
		if e = jobAudit(ctx, tx, i, "hold.matter.operation."+outcome, j); e != nil {
			return e
		}
		var live bool
		if e = tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, lease).Scan(&live); e != nil {
			return e
		}
		if !live {
			return ErrJobLeaseLost
		}
		if state != "cancel_requested" {
			return matterCurrent(ctx, tx, o)
		}
		return nil
	})
	return outcome, e
}
func (s *Store) MatterOperation(ctx context.Context, i Identity, name string, sequence int64) (map[string]any, error) {
	if e := matterAdmin(i, name); e != nil {
		return nil, e
	}
	if sequence < 1 {
		return nil, ErrMatterInput
	}
	var out map[string]any
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		o, e := operationRecord(ctx, tx, i.Tenant, name, sequence)
		if e != nil {
			return e
		}
		var processed, effected int64
		if e = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE outcome IN ('held','released')) FROM cratectl.hold_matter_outcomes WHERE operation=$1`, sequence).Scan(&processed, &effected); e != nil {
			return e
		}
		out = map[string]any{"operation": o.MatterOperation, "processed": processed, "effected": effected, "skipped": processed - effected, "remaining": int64(o.Plan.TargetCount) - processed, "retained_bytes": true}
		if o.jobSequence != nil && o.jobTask != nil {
			var j Job
			if e = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, *o.jobSequence, *o.jobTask), &j); e != nil {
				return e
			}
			out["job"] = j
			out["all_targets_processed"] = processed == int64(o.Plan.TargetCount) && j.State == "succeeded"
		}
		return nil
	})
	return out, e
}
