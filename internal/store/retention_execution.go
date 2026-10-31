// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func retentionIntent(ctx context.Context, tx pgx.Tx, tenant string, j Job) (RetentionPlan, Identity, error) {
	var p RetentionPlan
	requester := Identity{Tenant: tenant, Role: "admin"}
	var raw []byte
	var repo, name string
	var revision int64
	if j.Kind != "repository.retention" || j.Queue != "maintenance" {
		return p, requester, ErrRetentionInput
	}
	e := tx.QueryRow(ctx, `SELECT repository,name,revision,plan,requester_actor,requester_hash FROM cratectl.retention_runs WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&repo, &name, &revision, &raw, &requester.Actor, &requester.CredentialHash)
	if e != nil {
		return p, requester, e
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &p) != nil || p.Policy.Repository != repo || p.Policy.Name != name || p.Policy.Revision != revision || p.Policy.RetentionSettings.Validate() != nil || !p.Policy.Enabled || p.Targets < 0 || p.Targets > 10000 || p.Eligible < 0 || p.Eligible > p.Targets || p.SourceRevision < 0 || len(p.Items) != 0 || !uploadDigest.MatchString(p.Digest) || requester.CredentialHash == "" || p.BytesReclaimed != 0 {
		return p, requester, ErrRetentionInput
	}
	var count, last int64
	if e = tx.QueryRow(ctx, `SELECT count(*),COALESCE(max(ordinal),0) FROM cratectl.retention_items WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&count, &last); e != nil {
		return p, requester, e
	}
	if count != int64(p.Targets) || last != int64(p.Targets) {
		return p, requester, ErrRetentionInput
	}
	return p, requester, nil
}
func retentionRequester(ctx context.Context, tx pgx.Tx, requester Identity) error {
	e := checkIdentity(ctx, tx, requester)
	if errors.Is(e, ErrUnauthenticated) || errors.Is(e, ErrDenied) {
		return ErrRetentionAuthorization
	}
	return e
}
func retentionCurrent(ctx context.Context, tx pgx.Tx, i Identity, p RetentionPlan) error {
	if e := retentionRequester(ctx, tx, i); e != nil {
		return e
	}
	repo, e := retentionRepository(ctx, tx, i, p.Policy.Repository)
	if e != nil {
		return e
	}
	current, e := retentionPolicy(ctx, tx, p.Policy.Repository, p.Policy.Name)
	if e != nil {
		return e
	}
	if current.Revision != p.Policy.Revision || !current.Enabled || repo.SourceRevision != p.SourceRevision {
		return ErrRetentionChanged
	}
	return nil
}
func retentionTargetStatus(ctx context.Context, tx pgx.Tx, i Identity, p RetentionPlan, item RetentionItem) (string, int64, error) {
	if item.Ordinal < 1 || item.Ordinal > int64(p.Targets) || (IntegrityTarget{Repository: p.Policy.Repository, Path: item.Path, Digest: item.Digest, Size: item.Size}).Validate() != nil || !strings.HasSuffix(item.Path, "/manifests/sha256:"+item.Digest) || item.LifecycleRevision < 0 {
		return "", 0, ErrRetentionInput
	}
	switch item.Status {
	case "held", "tagged", "referenced", "newest", "young", "unvalidated":
		return item.Status, item.LifecycleRevision, nil
	case "eligible":
	default:
		return "", 0, ErrRetentionInput
	}
	state, e := artifactStateInTx(ctx, tx, p.Policy.Repository, item.Path)
	if e != nil {
		return "", 0, e
	}
	if state.Held {
		return "held", state.Revision, nil
	}
	if state.Deleted {
		return "already_retired", state.Revision, nil
	}
	if state.Revision != item.LifecycleRevision {
		return "changed", state.Revision, nil
	}
	var digest string
	var size int64
	var created time.Time
	var validated bool
	e = tx.QueryRow(ctx, `SELECT digest,size,created_at,COALESCE((metadata->>'oci_validated')='true',false) FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, p.Policy.Repository, item.Path).Scan(&digest, &size, &created, &validated)
	if errors.Is(e, pgx.ErrNoRows) {
		return "changed", state.Revision, nil
	}
	if e != nil {
		return "", 0, e
	}
	if digest != item.Digest || size != item.Size || !created.Equal(item.CreatedAt) {
		return "changed", state.Revision, nil
	}
	input := ArtifactStateRequest{Action: "hold", Path: item.Path, Digest: item.Digest, ExpectedRevision: state.Revision, Reason: p.Reason}
	preview, e := artifactStatePreview(ctx, tx, i, p.Policy.Repository, input, 128)
	if e != nil {
		return "", 0, e
	}
	if !p.Policy.ProtectTagged && !slices.Equal(item.Tags, preview.Tags) {
		return "changed", state.Revision, nil
	}
	image := strings.TrimSuffix(item.Path, "/manifests/sha256:"+item.Digest)
	var rank int64
	e = tx.QueryRow(ctx, `SELECT 1+count(*) FROM cratectl.artifacts a WHERE a.repository=$1 AND starts_with(a.path,$2||'/manifests/sha256:') AND a.path=$2||'/manifests/sha256:'||a.digest AND (a.created_at,a.path)>($3,$4) AND NOT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle l WHERE(l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path)AND l.deleted)`, p.Policy.Repository, image, created, item.Path).Scan(&rank)
	if e != nil {
		return "", 0, e
	}
	status := retentionStatus(p.Policy, preview, created, rank, validated, p.EvaluatedAt)
	if status != "eligible" {
		return status, state.Revision, nil
	}
	input.Action = "delete"
	value, _, e := changeArtifactState(ctx, tx, i, p.Policy.Repository, input, 128, nil)
	if e != nil {
		return "", 0, e
	}
	result, ok := value.(ArtifactStatePreview)
	if !ok {
		return "", 0, ErrRetentionInput
	}
	return "retired", result.Current.Revision, nil
}

// StepRetention processes one immutable target per fenced transaction. Mutable
// jobs.payload is only a public progress projection and is never execution authority.
func (s *Store) StepRetention(ctx context.Context, i WorkerIdentity, j Job) (string, error) {
	outcome := ""
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		p, requester, e := retentionIntent(ctx, tx, i.Tenant, j)
		if e != nil {
			return e
		}
		var lease time.Time
		if e = tx.QueryRow(ctx, `SELECT lease_until FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&lease); e != nil {
			return e
		}
		outcome = "cancelled"
		if state != "cancel_requested" {
			if e = retentionCurrent(ctx, tx, requester, p); e != nil {
				return e
			}
			var raw []byte
			var ordinal int64
			e = tx.QueryRow(ctx, `SELECT t.ordinal,t.target FROM cratectl.retention_items t WHERE t.sequence=$1 AND t.task=$2 AND NOT EXISTS(SELECT 1 FROM cratectl.retention_observations o WHERE(o.tenant,o.sequence,o.task,o.ordinal)=(t.tenant,t.sequence,t.task,t.ordinal))ORDER BY t.ordinal LIMIT 1`, j.Sequence, j.Task).Scan(&ordinal, &raw)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if e == nil {
				var item RetentionItem
				if len(raw) > 16384 || json.Unmarshal(raw, &item) != nil || item.Ordinal != ordinal {
					return ErrRetentionInput
				}
				status, revision, e := retentionTargetStatus(ctx, tx, requester, p, item)
				if e != nil {
					return e
				}
				if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_observations(tenant,sequence,task,ordinal,generation,status,lifecycle_revision,worker)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, i.Tenant, j.Sequence, j.Task, ordinal, j.Generation, status, revision, i.Actor); e != nil {
					return e
				}
				if e = appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "repository.retention.target", map[string]any{"job": j.ID(), "repository": p.Policy.Repository, "policy": p.Policy.Name, "policy_revision": p.Policy.Revision, "requester": requester.Actor, "ordinal": ordinal, "path": item.Path, "digest": item.Digest, "status": status, "lifecycle_revision": revision, "bytes_reclaimed": 0}, true); e != nil {
					return e
				}
			}
			var remaining bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.retention_items t WHERE t.sequence=$1 AND t.task=$2 AND NOT EXISTS(SELECT 1 FROM cratectl.retention_observations o WHERE(o.tenant,o.sequence,o.task,o.ordinal)=(t.tenant,t.sequence,t.task,t.ordinal)))`, j.Sequence, j.Task).Scan(&remaining); e != nil {
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
		if e = jobAudit(ctx, tx, i, "repository.retention."+outcome, j); e != nil {
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
			return retentionRequester(ctx, tx, requester)
		}
		return nil
	})
	return outcome, e
}

func (s *Store) RetentionRun(ctx context.Context, i Identity, id string) (map[string]any, error) {
	j, e := s.Job(ctx, i, id)
	if e != nil {
		return nil, e
	}
	var out map[string]any
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		p, _, e := retentionIntent(ctx, tx, i.Tenant, j)
		if e != nil {
			return e
		}
		if _, e = retentionRepositoryRecord(ctx, tx, i, p.Policy.Repository); e != nil {
			return e
		}
		var checked, retired int64
		if e = tx.QueryRow(ctx, `SELECT count(*),count(*)FILTER(WHERE status='retired') FROM cratectl.retention_observations WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&checked, &retired); e != nil {
			return e
		}
		out = map[string]any{"job": j, "plan": p, "processed": checked, "retired": retired, "skipped": checked - retired, "all_targets_processed": checked == int64(p.Targets) && j.State == "succeeded", "bytes_reclaimed": 0}
		return nil
	})
	return out, e
}

type RetentionOutcome struct {
	RetentionItem
	Outcome         string     `json:"outcome"`
	OutcomeRevision int64      `json:"outcome_revision"`
	ObservedAt      *time.Time `json:"observed_at,omitempty"`
}

func (s *Store) RetentionItems(ctx context.Context, i Identity, id string, after int64, limit int) ([]RetentionOutcome, bool, error) {
	out := []RetentionOutcome{}
	if after < 0 || limit < 1 || limit > 100 {
		return out, false, ErrRetentionInput
	}
	j, e := s.Job(ctx, i, id)
	if e != nil {
		return out, false, e
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		p, _, e := retentionIntent(ctx, tx, i.Tenant, j)
		if e != nil {
			return e
		}
		if _, e = retentionRepositoryRecord(ctx, tx, i, p.Policy.Repository); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT t.target,COALESCE(o.status,'pending'),COALESCE(o.lifecycle_revision,0),o.observed_at FROM cratectl.retention_items t LEFT JOIN cratectl.retention_observations o ON(o.tenant,o.sequence,o.task,o.ordinal)=(t.tenant,t.sequence,t.task,t.ordinal) WHERE t.sequence=$1 AND t.task=$2 AND t.ordinal>$3 ORDER BY t.ordinal LIMIT $4`, j.Sequence, j.Task, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v RetentionOutcome
			var raw []byte
			if e = rows.Scan(&raw, &v.Outcome, &v.OutcomeRevision, &v.ObservedAt); e != nil {
				return e
			}
			if len(raw) > 16384 || json.Unmarshal(raw, &v.RetentionItem) != nil {
				return ErrRetentionInput
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
