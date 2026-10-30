// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrRepairInput = errors.New("invalid repair request")
var ErrRepairChanged = errors.New("repair reference or source configuration changed")
var ErrRepairAuthorization = errors.New("repair requester authorization changed")
var ErrRepairReferences = errors.New("repair digest has conflicting retained size references")

type RepairRequest struct {
	Path                   string `json:"path"`
	Digest                 string `json:"digest"`
	ExpectedSourceRevision int64  `json:"expected_source_revision"`
	Reason                 string `json:"reason"`
	Provenance             string `json:"provenance"`
	DryRun                 bool   `json:"dry_run"`
}

func (r RepairRequest) Validate() error {
	if r.ExpectedSourceRevision < 0 || r.Path == "" || len(r.Path) > 2048 || !utf8.ValidString(r.Path) || strings.IndexFunc(r.Path, unicode.IsControl) >= 0 || len(r.Digest) != 64 || strings.Trim(r.Digest, "0123456789abcdef") != "" || !validLifecycleReason(r.Reason) || strings.TrimSpace(r.Reason) == "" || !utf8.ValidString(r.Reason) || !validLifecycleReason(r.Provenance) || strings.TrimSpace(r.Provenance) == "" || !utf8.ValidString(r.Provenance) {
		return ErrRepairInput
	}
	return nil
}

type RepairPlan struct {
	Target           IntegrityTarget          `json:"target"`
	SourceRevision   int64                    `json:"source_revision"`
	Root             string                   `json:"storage_identity"`
	Actor            string                   `json:"actor"`
	Reason           string                   `json:"reason"`
	Provenance       string                   `json:"provenance"`
	References       int64                    `json:"affected_references"`
	SourceReady      bool                     `json:"source_ready"`
	Installation     *blob.RepairInstallation `json:"installation,omitempty"`
	SecurityApproval bool                     `json:"security_approval"`
}
type repairPayload struct {
	RepairPlan
	Requester Identity           `json:"requester"`
	Source    *blob.RepairSource `json:"source,omitempty"`
}

// Job payloads may carry private execution fences. Only this allowlisted view
// leaves the store through management or worker claim responses.
func publicRepairPayload(raw json.RawMessage) (json.RawMessage, error) {
	var p RepairPlan
	if e := json.Unmarshal(raw, &p); e != nil {
		return nil, e
	}
	if p.Target.Validate() != nil || len(p.Root) != 64 {
		return nil, ErrRepairInput
	}
	return json.Marshal(p)
}
func repairReference(ctx context.Context, tx pgx.Tx, i Identity, repo, path, digest string, revision int64) (IntegrityTarget, error) {
	target := IntegrityTarget{Repository: repo, Path: path, Digest: digest}
	if i.Role != "admin" {
		return target, ErrDenied
	}
	r, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return target, e
	}
	if r.Mode == "group" {
		return target, ErrRepairInput
	}
	if r.SourceRevision != revision {
		return target, ErrRepairChanged
	}
	var current string
	e = tx.QueryRow(ctx, `SELECT digest,size FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, path).Scan(&current, &target.Size)
	if errors.Is(e, pgx.ErrNoRows) {
		return target, ErrNotFound
	}
	if e != nil {
		return target, e
	}
	if current != digest {
		return target, ErrRepairChanged
	}
	if target.Validate() != nil {
		return target, ErrRepairInput
	}
	return target, nil
}
func (s *Store) PreviewRepair(ctx context.Context, i Identity, repo string, input RepairRequest, budget int) (RepairPlan, error) {
	var out RepairPlan
	if input.Validate() != nil || budget < 1 || budget > 1000000 {
		return out, ErrRepairInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; out, e = repairPreview(ctx, tx, i, repo, input, budget); return e })
	return out, e
}
func repairPreview(ctx context.Context, tx pgx.Tx, i Identity, repo string, input RepairRequest, budget int) (RepairPlan, error) {
	out := RepairPlan{SourceRevision: input.ExpectedSourceRevision, Actor: i.Actor, Reason: input.Reason, Provenance: input.Provenance}
	if input.Validate() != nil || budget < 1 || budget > 1000000 {
		return out, ErrRepairInput
	}
	var e error
	out.Target, e = repairReference(ctx, tx, i, repo, input.Path, input.Digest, input.ExpectedSourceRevision)
	if e != nil {
		return out, e
	}
	var conflict bool
	e = tx.QueryRow(ctx, `SELECT count(*),COALESCE(bool_or(size<>$2),false) FROM (SELECT size FROM cratectl.artifacts WHERE digest=$1 UNION ALL SELECT size FROM cratectl.upload_parts WHERE digest=$1)r`, input.Digest, out.Target.Size).Scan(&out.References, &conflict)
	if e != nil {
		return out, e
	}
	if conflict {
		return out, ErrRepairReferences
	}
	if out.References > int64(budget) {
		return out, ErrSweepBudget
	}
	return out, nil
}
func (s *Store) StartRepair(ctx context.Context, i Identity, repo, key, fp, root string, input RepairRequest, budget int) (Result, error) {
	if input.DryRun {
		preview, e := s.PreviewRepair(ctx, i, repo, input, budget)
		preview.Root = root
		return jsonResult(preview, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "storage.repair.requested", true, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		_, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
		return e
	}, func(tx pgx.Tx) (any, int, error) {
		if i.CredentialHash == "" || len(root) != 64 {
			return nil, 0, ErrRepairInput
		}
		plan, e := repairPreview(ctx, tx, i, repo, input, budget)
		if e != nil {
			return nil, 0, e
		}
		plan.Root = root
		policy, e := queuePolicy(ctx, tx, i.Tenant, "integrity")
		if e != nil {
			return nil, 0, e
		}
		if e = queueRoom(ctx, tx, policy, 1); e != nil {
			return nil, 0, e
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		task := "repair-" + crypt.Digest([]byte(i.Actor+"\x00"+key+"\x00"+fp))
		raw, e := json.Marshal(repairPayload{RepairPlan: plan, Requester: i})
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload)VALUES($1,$2,$3,'integrity','storage.repair',$4)`, i.Tenant, sequence, task, raw); e != nil {
			return nil, 0, e
		}
		return map[string]any{"repository": plan.Target.Repository, "path": plan.Target.Path, "digest": plan.Target.Digest, "job": (Job{Sequence: sequence, Task: task}).ID(), "plan": plan, "state": "awaiting_source", "security_approval": false}, 202, nil
	})
}
func repairInTx(ctx context.Context, tx pgx.Tx, sequence int64, task string) (repairPayload, error) {
	var p repairPayload
	var raw []byte
	var tenant string
	e := tx.QueryRow(ctx, `SELECT payload,tenant FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND kind='storage.repair'`, sequence, task).Scan(&raw, &tenant)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	if e != nil {
		return p, e
	}
	if len(raw) > 64<<10 || json.Unmarshal(raw, &p) != nil || p.Requester.Tenant != tenant || p.Actor != p.Requester.Actor || p.Target.Validate() != nil || len(p.Root) != 64 {
		return p, ErrRepairInput
	}
	return p, nil
}
func currentRepair(ctx context.Context, tx pgx.Tx, p repairPayload) error {
	if p.Requester.CredentialHash == "" || p.Requester.Role != "admin" {
		return ErrRepairAuthorization
	}
	if e := checkIdentity(ctx, tx, p.Requester); e != nil {
		if errors.Is(e, ErrUnauthenticated) {
			return ErrRepairAuthorization
		}
		return e
	}
	target, e := repairReference(ctx, tx, p.Requester, p.Target.Repository, p.Target.Path, p.Target.Digest, p.SourceRevision)
	if e != nil {
		return e
	}
	if target.Size != p.Target.Size {
		return ErrRepairChanged
	}
	var conflict bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE digest=$1 AND size<>$2 UNION ALL SELECT 1 FROM cratectl.upload_parts WHERE digest=$1 AND size<>$2)`, p.Target.Digest, p.Target.Size).Scan(&conflict); e != nil {
		return e
	}
	if conflict {
		return ErrRepairReferences
	}
	return nil
}
func (s *Store) RepairForSource(ctx context.Context, i Identity, id string) (RepairPlan, error) {
	var out RepairPlan
	if i.Role != "admin" {
		return out, ErrDenied
	}
	sequence, task, e := ParseJobID(id)
	if e != nil {
		return out, e
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		p, e := repairInTx(ctx, tx, sequence, task)
		if e != nil {
			return e
		}
		if p.Requester.CredentialHash != i.CredentialHash {
			return ErrRepairAuthorization
		}
		if e = currentRepair(ctx, tx, p); e != nil {
			return e
		}
		out = p.RepairPlan
		return nil
	})
	return out, e
}
func (s *Store) AcceptRepairSource(ctx context.Context, i Identity, id, key, fp string, source blob.RepairSource) (Result, error) {
	sequence, task, e := ParseJobID(id)
	if e != nil {
		return Result{}, e
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "storage.repair.source.accepted", true, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		p, e := repairInTx(ctx, tx, sequence, task)
		if e != nil {
			return e
		}
		if p.Requester.CredentialHash != i.CredentialHash {
			return ErrRepairAuthorization
		}
		return currentRepair(ctx, tx, p)
	}, func(tx pgx.Tx) (any, int, error) {
		p, e := repairInTx(ctx, tx, sequence, task)
		if e != nil {
			return nil, 0, e
		}
		var state string
		if e = tx.QueryRow(ctx, `SELECT state FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, sequence, task).Scan(&state); e != nil {
			return nil, 0, e
		}
		if p.SourceReady || p.Source != nil || state != "pending" && state != "retry" || source.Digest != p.Target.Digest || source.Size != p.Target.Size || len(source.Root) != 64 || len(source.File) != 64 {
			return nil, 0, ErrRepairChanged
		}
		p.Source = &source
		p.SourceReady = true
		raw, e := json.Marshal(p)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.jobs SET payload=$1,available_at=clock_timestamp(),updated_at=clock_timestamp() WHERE sequence=$2 AND task=$3`, raw, sequence, task); e != nil {
			return nil, 0, e
		}
		return map[string]any{"repository": p.Target.Repository, "path": p.Target.Path, "digest": p.Target.Digest, "job": id, "state": "queued", "target": p.Target, "source_ready": true, "security_approval": false}, 202, nil
	})
}
func (s *Store) JobRepair(ctx context.Context, i WorkerIdentity, j Job) (RepairPlan, blob.RepairSource, error) {
	var p repairPayload
	if j.Kind != "storage.repair" || j.Queue != "integrity" {
		return p.RepairPlan, blob.RepairSource{}, ErrRepairInput
	}
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		p, e = repairInTx(ctx, tx, j.Sequence, j.Task)
		if e != nil {
			return e
		}
		if !p.SourceReady || p.Source == nil {
			return ErrRepairInput
		}
		return currentRepair(ctx, tx, p)
	})
	if e != nil {
		return p.RepairPlan, blob.RepairSource{}, e
	}
	return p.RepairPlan, *p.Source, nil
}
func (s *Store) ApplyRepair(ctx context.Context, i WorkerIdentity, j Job, install func(context.Context) (blob.RepairInstallation, error)) error {
	return s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		p, e := repairInTx(ctx, tx, j.Sequence, j.Task)
		if e != nil {
			return e
		}
		if !p.SourceReady || p.Source == nil {
			return ErrRepairInput
		}
		if e = currentRepair(ctx, tx, p); e != nil {
			return e
		}
		var until time.Time
		if e = tx.QueryRow(ctx, `SELECT lease_until FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&until); e != nil {
			return e
		}
		effect, done := context.WithDeadline(ctx, until)
		defer done()
		receipt, e := install(effect)
		if e != nil {
			return e
		}
		if p.Installation == nil || receipt.Installed {
			p.Installation = &receipt
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.jobs SET payload=$1,updated_at=clock_timestamp() WHERE sequence=$2 AND task=$3`, raw, j.Sequence, j.Task); e != nil {
			return e
		}
		return appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "storage.repair.installed", map[string]any{"repository": p.Target.Repository, "path": p.Target.Path, "digest": p.Target.Digest, "job": j.ID(), "target": p.Target, "generation": j.Generation, "receipt": receipt, "security_approval": false}, false)
	})
}
func (s *Store) FinishRepair(ctx context.Context, i WorkerIdentity, j Job, status string) (string, error) {
	switch status {
	case "verified", "missing", "corrupt", "io_error", "limit", "timeout":
	default:
		return "", ErrRepairInput
	}
	return s.finishJob(ctx, i, j, func(tx pgx.Tx) (string, string, error) {
		p, e := repairInTx(ctx, tx, j.Sequence, j.Task)
		if e != nil {
			return "", "", e
		}
		if p.Installation == nil {
			return "", "", ErrRepairInput
		}
		if e = currentRepair(ctx, tx, p); e != nil {
			return "", "", e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.integrity_observations(tenant,sequence,task,generation,repository,digest,size,status,worker)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, i.Tenant, j.Sequence, j.Task, j.Generation, p.Target.Repository, p.Target.Digest, p.Target.Size, status, j.Worker); e != nil {
			return "", "", e
		}
		if status == "verified" {
			return "succeeded", "", nil
		}
		if status == "limit" {
			return "failed", "repair_readback_limit", nil
		}
		return "retry", "repair_readback_" + status, nil
	})
}
