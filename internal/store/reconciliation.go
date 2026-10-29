// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type ReconciliationRequest struct {
	Repository string `json:"repository,omitempty"`
	PageSize   int    `json:"page_size"`
}

func (r ReconciliationRequest) Validate() error {
	if r.Repository != "" && !Name.MatchString(r.Repository) || r.PageSize < 1 || r.PageSize > 1000 {
		return ErrConflict
	}
	return nil
}

type ReconciliationProgress struct {
	ReconciliationRequest
	Cutoff                   time.Time `json:"cutoff"`
	Phase                    string    `json:"phase"`
	AfterRepository          string    `json:"after_repository,omitempty"`
	AfterPath                string    `json:"after_path,omitempty"`
	Pages                    int64     `json:"pages"`
	RetrievalsReleased       int64     `json:"retrievals_released"`
	UploadOperationsReleased int64     `json:"upload_operations_released"`
	UploadsExpired           int64     `json:"uploads_expired"`
}
type LeaseCandidate struct {
	Repository string `json:"repository"`
	Subject    string `json:"subject"`
	Kind       string `json:"kind"`
	Generation int64  `json:"generation"`
}

const retrievalCandidates = `SELECT repository,path,'retrieval',generation FROM cratectl.retrievals WHERE state='fetching' AND lease_until<=$1 AND lease_until<=clock_timestamp() AND ($2='' OR repository=$2) AND (repository,path)>($3,$4) ORDER BY repository,path LIMIT $5`
const uploadCandidates = `SELECT repository,id,CASE WHEN expires_at<=$1 AND expires_at<=clock_timestamp() THEN 'upload' ELSE 'upload_operation' END,generation FROM cratectl.uploads WHERE state='active' AND ((expires_at<=$1 AND expires_at<=clock_timestamp()) OR (operation_token<>'' AND operation_until<=$1 AND operation_until<=clock_timestamp())) AND ($2='' OR repository=$2) AND (repository,id)>($3,$4) ORDER BY repository,id LIMIT $5`

func leaseCandidates(ctx context.Context, tx pgx.Tx, p ReconciliationProgress, limit int) ([]LeaseCandidate, error) {
	query := retrievalCandidates
	if p.Phase == "uploads" {
		query = uploadCandidates
	} else if p.Phase != "retrievals" {
		return nil, ErrConflict
	}
	rows, e := tx.Query(ctx, query, p.Cutoff, p.Repository, p.AfterRepository, p.AfterPath, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []LeaseCandidate{}
	for rows.Next() {
		var c LeaseCandidate
		if e = rows.Scan(&c.Repository, &c.Subject, &c.Kind, &c.Generation); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Preview is a bounded sample at a database-clock cutoff. Execution takes its own
// cutoff and rechecks every candidate; this is not a reservation or deletion plan.
func (s *Store) PreviewReconciliation(ctx context.Context, i Identity, r ReconciliationRequest) (map[string]any, error) {
	if i.Role != "admin" {
		return nil, ErrDenied
	}
	if e := r.Validate(); e != nil {
		return nil, e
	}
	out := map[string]any{"bytes_deleted": 0, "scope": "Expired retrieval and OCI upload leases only. Current operations are rechecked during execution."}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if r.Repository != "" {
			if _, e := repositoryInTx(ctx, tx, i, r.Repository, "read"); e != nil {
				return e
			}
		}
		p := ReconciliationProgress{ReconciliationRequest: r}
		if e := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&p.Cutoff); e != nil {
			return e
		}
		out["cutoff"] = p.Cutoff
		for _, phase := range []string{"retrievals", "uploads"} {
			p.Phase = phase
			items, e := leaseCandidates(ctx, tx, p, r.PageSize+1)
			if e != nil {
				return e
			}
			more := len(items) > r.PageSize
			if more {
				items = items[:r.PageSize]
			}
			out[phase] = map[string]any{"items": items, "more": more}
		}
		return nil
	})
	return out, e
}
func (s *Store) StartReconciliation(ctx context.Context, i Identity, key, fingerprint string, r ReconciliationRequest) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if e := r.Validate(); e != nil {
		return Result{}, e
	}
	token, e := crypt.Token()
	if e != nil {
		return Result{}, e
	}
	task := "reconcile-" + crypt.Digest([]byte(token))
	return s.mutateIntent(ctx, i, key, fingerprint, "maintenance.reconciliation.requested", false, func(tx pgx.Tx) (any, int, error) {
		if r.Repository != "" {
			if _, e := repositoryInTx(ctx, tx, i, r.Repository, "read"); e != nil {
				return nil, 0, e
			}
		}
		policy, e := queuePolicy(ctx, tx, i.Tenant, "maintenance")
		if e != nil {
			return nil, 0, e
		}
		if e = queueRoom(ctx, tx, policy, 1); e != nil {
			return nil, 0, e
		}
		p := ReconciliationProgress{ReconciliationRequest: r, Phase: "retrievals"}
		if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&p.Cutoff); e != nil {
			return nil, 0, e
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload) VALUES($1,$2,$3,'maintenance','leases.reconcile',$4)`, i.Tenant, sequence, task, raw); e != nil {
			return nil, 0, e
		}
		return map[string]any{"job": (Job{Sequence: sequence, Task: task}).ID(), "queue": "maintenance", "progress": p, "bytes_deleted": 0}, 202, nil
	})
}

// ReconcileLeases commits one bounded page and its cursor together. Yielding
// resets only the consecutive failure budget and gives other ready work a turn.
func (s *Store) ReconcileLeases(ctx context.Context, i WorkerIdentity, j Job) (string, error) {
	outcome := ""
	if j.Queue != "maintenance" || j.Kind != "leases.reconcile" {
		return outcome, ErrConflict
	}
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		var raw []byte
		if e = tx.QueryRow(ctx, `SELECT payload FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task).Scan(&raw); e != nil {
			return e
		}
		var p ReconciliationProgress
		if len(raw) > 8192 || json.Unmarshal(raw, &p) != nil || p.Validate() != nil || p.Cutoff.IsZero() || p.Phase != "retrievals" && p.Phase != "uploads" && p.Phase != "done" {
			return ErrConflict
		}
		outcome = "cancelled"
		actor := Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}
		if state != "cancel_requested" {
			outcome = "pending"
			if p.Phase != "done" {
				items, e := leaseCandidates(ctx, tx, p, p.PageSize)
				if e != nil {
					return e
				}
				for _, c := range items {
					sequence, e := nextEventSequence(ctx, tx, actor)
					if e != nil {
						return e
					}
					var changed int64
					if c.Kind == "retrieval" {
						tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET state='failed',generation=generation+1,lease_token='',lease_until='epoch',fresh_until='epoch',last_error='lease_recovered',validation_root='',validation_generation=0,changed_at=clock_timestamp(),change_sequence=$1 WHERE repository=$2 AND path=$3 AND generation=$4 AND state='fetching' AND lease_until<=$5 AND lease_until<=clock_timestamp()`, sequence, c.Repository, c.Subject, c.Generation, p.Cutoff)
						if e != nil {
							return e
						}
						changed = tag.RowsAffected()
						p.RetrievalsReleased += changed
					} else {
						expire := c.Kind == "upload"
						tag, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET state=CASE WHEN $1 THEN 'expired' ELSE state END,generation=generation+1,operation_token='',operation_until='epoch' WHERE repository=$2 AND id=$3 AND generation=$4 AND state='active' AND (($1 AND expires_at<=$5 AND expires_at<=clock_timestamp()) OR (NOT $1 AND operation_token<>'' AND operation_until<=$5 AND operation_until<=clock_timestamp()))`, expire, c.Repository, c.Subject, c.Generation, p.Cutoff)
						if e != nil {
							return e
						}
						changed = tag.RowsAffected()
						if expire {
							p.UploadsExpired += changed
						} else {
							p.UploadOperationsReleased += changed
						}
					}
					if changed > 0 {
						if e = appendEventIntent(ctx, tx, actor, "maintenance.lease.recovered", map[string]any{"job": j.ID(), "repository": c.Repository, "subject": c.Subject, "kind": c.Kind, "previous_generation": c.Generation, "bytes_deleted": 0}, false); e != nil {
							return e
						}
					}
					p.AfterRepository, p.AfterPath = c.Repository, c.Subject
				}
				p.Pages++
				if len(items) < p.PageSize {
					p.AfterRepository, p.AfterPath = "", ""
					if p.Phase == "retrievals" {
						p.Phase = "uploads"
					} else {
						p.Phase = "done"
					}
				}
			}
			if p.Phase == "done" {
				outcome = "succeeded"
			}
		}
		raw, e = json.Marshal(p)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET state=$1,payload=$2,cycle_attempts=CASE WHEN $1='pending' THEN 0 ELSE cycle_attempts END,lease_token='',lease_until='epoch',available_at=clock_timestamp(),updated_at=clock_timestamp(),finished_at=CASE WHEN $1='pending' THEN NULL ELSE clock_timestamp() END WHERE sequence=$3 AND task=$4 AND generation=$5 AND lease_token=$6 AND lease_until>clock_timestamp()`, outcome, raw, j.Sequence, j.Task, j.Generation, j.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrJobLeaseLost
		}
		j.State = outcome
		return appendEventIntent(ctx, tx, actor, "maintenance.reconciliation."+outcome, map[string]any{"job": j.ID(), "generation": j.Generation, "progress": p, "bytes_deleted": 0}, false)
	})
	return outcome, e
}
