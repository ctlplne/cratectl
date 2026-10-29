// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrSweepBudget = errors.New("integrity snapshot exceeds operator target budget")

type SweepRequest struct {
	Repository string `json:"repository,omitempty"`
}

func (r SweepRequest) Validate() error {
	if r.Repository != "" && !Name.MatchString(r.Repository) {
		return ErrConflict
	}
	return nil
}

type SweepProgress struct {
	SweepRequest
	Cutoff             time.Time `json:"cutoff"`
	Targets            int64     `json:"targets"`
	ArtifactReferences int64     `json:"artifact_references"`
	UploadParts        int64     `json:"upload_parts"`
	AfterOrdinal       int64     `json:"after_ordinal"`
	Checked            int64     `json:"checked"`
	Verified           int64     `json:"verified"`
	Issues             int64     `json:"issues"`
	Pass               int64     `json:"pass"`
}

func (p SweepProgress) Validate() error {
	if p.SweepRequest.Validate() != nil || p.Cutoff.IsZero() || p.Targets < 0 || p.Targets > 2147483646 || p.ArtifactReferences < 0 || p.UploadParts < 0 || p.AfterOrdinal != p.Checked || p.Checked < 0 || p.Checked > p.Targets || p.Verified < 0 || p.Verified > p.Checked || p.Issues < 0 || p.Issues > p.Checked || p.Verified+p.Issues != p.Checked || p.Pass < 1 {
		return ErrConflict
	}
	return nil
}

type SweepItem struct {
	Ordinal            int64      `json:"ordinal"`
	Repository         string     `json:"repository"`
	Digest             string     `json:"digest"`
	Size               int64      `json:"size"`
	Path               string     `json:"path"`
	ArtifactReferences int64      `json:"artifact_references"`
	UploadParts        int64      `json:"upload_parts"`
	ReferenceConflict  bool       `json:"reference_conflict"`
	Status             string     `json:"status"`
	ObservedAt         *time.Time `json:"observed_at,omitempty"`
	Generation         int64      `json:"generation,omitempty"`
}

const sweepItemColumns = `ordinal,repository,digest,size,path,artifact_references,upload_parts,reference_conflict`
const sweepBindings = `WITH bindings AS (
 SELECT repository,digest,size,path,1::bigint artifact_references,0::bigint upload_parts FROM cratectl.artifacts WHERE ($1='' OR repository=$1)
 UNION ALL
 SELECT u.repository,p.digest,p.size,'oci-upload/'||u.id||'/'||p.offset_bytes::text,0::bigint,1::bigint FROM cratectl.upload_parts p JOIN cratectl.uploads u ON(u.tenant,u.id)=(p.tenant,p.upload_id) WHERE ($1='' OR u.repository=$1)
), grouped AS (
 SELECT repository,digest,size,min(path) path,sum(artifact_references)::bigint artifact_references,sum(upload_parts)::bigint upload_parts FROM bindings GROUP BY repository,digest,size
), limited AS (
 SELECT *,min(size) OVER(PARTITION BY digest)<>max(size) OVER(PARTITION BY digest) reference_conflict FROM grouped ORDER BY repository,digest,size LIMIT $2
) `

func scanSweepItem(row pgx.Row, item *SweepItem) error {
	return row.Scan(&item.Ordinal, &item.Repository, &item.Digest, &item.Size, &item.Path, &item.ArtifactReferences, &item.UploadParts, &item.ReferenceConflict)
}
func (s *Store) PreviewSweep(ctx context.Context, i Identity, r SweepRequest, limit int) ([]SweepItem, bool, error) {
	out := []SweepItem{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if r.Validate() != nil || limit < 1 || limit > 1000 {
		return out, false, ErrConflict
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if r.Repository != "" {
			if _, e := repositoryInTx(ctx, tx, i, r.Repository, "read"); e != nil {
				return e
			}
		}
		rows, e := tx.Query(ctx, sweepBindings+`SELECT row_number() OVER(ORDER BY repository,digest,size),repository,digest,size,path,artifact_references,upload_parts,reference_conflict FROM limited ORDER BY repository,digest,size`, r.Repository, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var item SweepItem
			if e = scanSweepItem(rows, &item); e != nil {
				return e
			}
			item.Status = "pending"
			out = append(out, item)
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
func (s *Store) StartSweep(ctx context.Context, i Identity, key, fingerprint string, r SweepRequest, budget int) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if r.Validate() != nil || budget < 1 || budget > 2147483646 {
		return Result{}, ErrConflict
	}
	token, e := crypt.Token()
	if e != nil {
		return Result{}, e
	}
	task := "sweep-" + crypt.Digest([]byte(token))
	return s.mutateIntent(ctx, i, key, fingerprint, "storage.sweep.requested", false, func(tx pgx.Tx) (any, int, error) {
		if r.Repository != "" {
			if _, e := repositoryInTx(ctx, tx, i, r.Repository, "read"); e != nil {
				return nil, 0, e
			}
		}
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
		p, e := snapshotBindings(ctx, tx, i, sequence, task, r, budget)
		if e != nil {
			return nil, 0, e
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload) VALUES($1,$2,$3,'integrity','storage.sweep',$4)`, i.Tenant, sequence, task, raw); e != nil {
			return nil, 0, e
		}
		return map[string]any{"job": (Job{Sequence: sequence, Task: task}).ID(), "queue": "integrity", "progress": p, "security_approval": false}, 202, nil
	})
}
func sweepProgress(raw []byte) (SweepProgress, error) {
	var p SweepProgress
	if len(raw) > 8192 || json.Unmarshal(raw, &p) != nil || p.Validate() != nil {
		return p, ErrConflict
	}
	return p, nil
}
func loadSweep(ctx context.Context, tx pgx.Tx, j Job) (SweepProgress, error) {
	if j.Queue != "integrity" || j.Kind != "storage.sweep" {
		return SweepProgress{}, ErrConflict
	}
	var raw []byte
	if e := tx.QueryRow(ctx, `SELECT payload FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND kind='storage.sweep'`, j.Sequence, j.Task).Scan(&raw); e != nil {
		return SweepProgress{}, e
	}
	return sweepProgress(raw)
}
func (s *Store) NextSweepItem(ctx context.Context, i WorkerIdentity, j Job) (SweepItem, bool, error) {
	var item SweepItem
	empty := false
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		p, e := loadSweep(ctx, tx, j)
		if e != nil {
			return e
		}
		if p.Checked == p.Targets {
			empty = true
			return nil
		}
		return scanSweepItem(tx.QueryRow(ctx, `SELECT `+sweepItemColumns+` FROM cratectl.sweep_items WHERE sequence=$1 AND task=$2 AND ordinal=$3`, j.Sequence, j.Task, p.AfterOrdinal+1), &item)
	})
	return item, empty, e
}
func (s *Store) FinishSweepItem(ctx context.Context, i WorkerIdentity, j Job, item SweepItem, status string) (string, error) {
	switch status {
	case "verified", "missing", "corrupt", "io_error", "limit", "timeout":
	case "":
		if item.Ordinal != 0 {
			return "", ErrConflict
		}
	default:
		return "", ErrConflict
	}
	outcome := ""
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		p, e := loadSweep(ctx, tx, j)
		if e != nil {
			return e
		}
		outcome = "cancelled"
		if state != "cancel_requested" {
			if p.Checked < p.Targets {
				var target SweepItem
				if e = scanSweepItem(tx.QueryRow(ctx, `SELECT `+sweepItemColumns+` FROM cratectl.sweep_items WHERE sequence=$1 AND task=$2 AND ordinal=$3`, j.Sequence, j.Task, p.AfterOrdinal+1), &target); e != nil {
					return e
				}
				if item.Ordinal != target.Ordinal || item.Repository != target.Repository || item.Digest != target.Digest || item.Size != target.Size || status == "" {
					return ErrConflict
				}
				if target.ReferenceConflict && status == "verified" {
					status = "inconsistent"
				}
				if _, e = tx.Exec(ctx, `INSERT INTO cratectl.integrity_observations(tenant,sequence,task,generation,repository,digest,size,status,worker,ordinal,pass) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, i.Tenant, j.Sequence, j.Task, j.Generation, target.Repository, target.Digest, target.Size, status, j.Worker, target.Ordinal, p.Pass); e != nil {
					return e
				}
				p.AfterOrdinal = target.Ordinal
				p.Checked++
				if status == "verified" {
					p.Verified++
				} else {
					p.Issues++
				}
			} else if item.Ordinal != 0 || status != "" {
				return ErrConflict
			}
			outcome = "pending"
			if p.Checked == p.Targets {
				outcome = "succeeded"
			}
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET payload=$1,state=$2,cycle_attempts=CASE WHEN $2='pending' THEN 0 ELSE cycle_attempts END,available_at=clock_timestamp(),lease_token='',lease_until='epoch',updated_at=clock_timestamp(),finished_at=CASE WHEN $2='pending' THEN NULL ELSE clock_timestamp() END WHERE sequence=$3 AND task=$4 AND generation=$5 AND lease_token=$6 AND lease_until>clock_timestamp()`, raw, outcome, j.Sequence, j.Task, j.Generation, j.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrJobLeaseLost
		}
		return appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "storage.sweep."+outcome, map[string]any{"job": j.ID(), "generation": j.Generation, "ordinal": item.Ordinal, "status": status, "progress": p, "security_approval": false}, false)
	})
	return outcome, e
}
func (s *Store) Sweep(ctx context.Context, i Identity, id string) (map[string]any, error) {
	j, e := s.Job(ctx, i, id)
	if e != nil {
		return nil, e
	}
	if j.Kind != "storage.sweep" {
		return nil, ErrNotFound
	}
	p, e := sweepProgress(j.Target)
	if e != nil {
		return nil, e
	}
	complete := j.State == "succeeded" && p.Checked == p.Targets
	return map[string]any{"job": j, "all_targets_assessed": complete, "integrity_clean": complete && p.Issues == 0, "security_approval": false, "scope": "Immutable snapshot of current artifact and retained upload-part repository/digest/size bindings. Unreferenced CAS and temporary files are outside this snapshot."}, nil
}
func (s *Store) SweepItems(ctx context.Context, i Identity, id string, after int64, limit int) ([]SweepItem, bool, error) {
	return s.referenceSnapshotItems(ctx, i, id, after, limit, "storage.sweep")
}
func (s *Store) referenceSnapshotItems(ctx context.Context, i Identity, id string, after int64, limit int, kind string) ([]SweepItem, bool, error) {
	out := []SweepItem{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if after < 0 || limit < 1 || limit > 1000 {
		return out, false, ErrConflict
	}
	sequence, task, e := ParseJobID(id)
	if e != nil {
		return out, false, e
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var j Job
		if e := scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND kind=$3`, sequence, task, kind), &j); e != nil {
			return e
		}
		var pass int64
		if kind == "storage.inventory" {
			p, e := inventoryProgress(j.Target)
			if e != nil {
				return e
			}
			pass = p.Pass
		} else {
			p, e := sweepProgress(j.Target)
			if e != nil {
				return e
			}
			pass = p.Pass
		}
		rows, e := tx.Query(ctx, `SELECT t.ordinal,t.repository,t.digest,t.size,t.path,t.artifact_references,t.upload_parts,t.reference_conflict,COALESCE(o.status,'pending'),o.observed_at,COALESCE(o.generation,0) FROM cratectl.sweep_items t LEFT JOIN LATERAL(SELECT status,observed_at,generation FROM cratectl.integrity_observations WHERE sequence=t.sequence AND task=t.task AND ordinal=t.ordinal AND pass=$1 ORDER BY generation DESC LIMIT 1)o ON true WHERE t.sequence=$2 AND t.task=$3 AND t.ordinal>$4 ORDER BY t.ordinal LIMIT $5`, pass, sequence, task, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var item SweepItem
			if e = rows.Scan(&item.Ordinal, &item.Repository, &item.Digest, &item.Size, &item.Path, &item.ArtifactReferences, &item.UploadParts, &item.ReferenceConflict, &item.Status, &item.ObservedAt, &item.Generation); e != nil {
				return e
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
func resetCompletedSweep(j *Job) ([]byte, error) {
	p, e := sweepProgress(j.Target)
	if e != nil {
		return nil, e
	}
	if p.Pass == int64(^uint64(0)>>1) {
		return nil, fmt.Errorf("%w: sweep pass exhausted", ErrConflict)
	}
	p.AfterOrdinal, p.Checked, p.Verified, p.Issues = 0, 0, 0, 0
	p.Pass++
	return json.Marshal(p)
}

func snapshotBindings(ctx context.Context, tx pgx.Tx, i Identity, sequence int64, task string, r SweepRequest, budget int) (SweepProgress, error) {
	// Source references cannot change while this tenant mutation lock is held.
	// The snapshot includes all states, aliases and retained upload part bindings.
	tag, e := tx.Exec(ctx, sweepBindings+`INSERT INTO cratectl.sweep_items(tenant,sequence,task,ordinal,repository,digest,size,path,artifact_references,upload_parts,reference_conflict) SELECT $3,$4,$5,row_number() OVER(ORDER BY repository,digest,size),repository,digest,size,path,artifact_references,upload_parts,reference_conflict FROM limited`, r.Repository, budget+1, i.Tenant, sequence, task)
	if e != nil {
		return SweepProgress{}, e
	}
	if tag.RowsAffected() > int64(budget) {
		return SweepProgress{}, ErrSweepBudget
	}
	p := SweepProgress{SweepRequest: r, Targets: tag.RowsAffected(), Pass: 1}
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&p.Cutoff); e != nil {
		return SweepProgress{}, e
	}
	if e = tx.QueryRow(ctx, `SELECT COALESCE(sum(artifact_references),0)::bigint,COALESCE(sum(upload_parts),0)::bigint FROM cratectl.sweep_items WHERE sequence=$1 AND task=$2`, sequence, task).Scan(&p.ArtifactReferences, &p.UploadParts); e != nil {
		return SweepProgress{}, e
	}
	return p, nil
}
