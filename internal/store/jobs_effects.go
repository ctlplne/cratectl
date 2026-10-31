// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type EventProjection struct {
	Position   int64  `json:"position"`
	Sequence   int64  `json:"sequence"`
	Hash       string `json:"event_hash"`
	Actor      string `json:"actor"`
	Kind       string `json:"kind"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Digest     string `json:"digest"`
}

func (s *Store) JobEvent(ctx context.Context, i WorkerIdentity, j Job, limit int64) (EventProjection, error) {
	var p EventProjection
	if limit < 1 || limit > 1<<30 || j.Queue != "events" {
		return p, ErrConflict
	}
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		var length int64
		if e = tx.QueryRow(ctx, `SELECT octet_length(payload) FROM cratectl.events WHERE sequence=$1`, j.Sequence).Scan(&length); e != nil {
			return e
		}
		if length > limit {
			return ErrMetadataLimit
		}
		var raw, previous, hash string
		if e = tx.QueryRow(ctx, `SELECT payload,previous_hash,hash FROM cratectl.events WHERE sequence=$1`, j.Sequence).Scan(&raw, &previous, &hash); e != nil {
			return e
		}
		if crypt.Digest([]byte(previous+"\n"+raw)) != hash {
			return ErrConflict
		}
		if j.Sequence > 1 {
			var expected string
			if e = tx.QueryRow(ctx, `SELECT hash FROM cratectl.events WHERE sequence=$1`, j.Sequence-1).Scan(&expected); e != nil {
				return e
			}
			if expected != previous {
				return ErrConflict
			}
		} else if previous != "" {
			return ErrConflict
		}
		var envelope struct {
			Tenant, Actor, Kind string
			Sequence            int64
			Data                json.RawMessage
		}
		if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.Tenant != i.Tenant || envelope.Sequence != j.Sequence || envelope.Kind != j.Kind {
			return ErrConflict
		}
		var coordinate struct{ Repository, Path, Digest string }
		json.Unmarshal(envelope.Data, &coordinate)
		if len(coordinate.Repository) > 63 || len(coordinate.Path) > 2048 || len(coordinate.Digest) > 128 {
			return ErrMetadataLimit
		}
		p = EventProjection{Sequence: j.Sequence, Hash: hash, Actor: envelope.Actor, Kind: envelope.Kind, Repository: coordinate.Repository, Path: coordinate.Path, Digest: coordinate.Digest}
		return nil
	})
	return p, e
}
func (s *Store) JobIntegrityTarget(ctx context.Context, i WorkerIdentity, j Job) (IntegrityTarget, bool, error) {
	var target IntegrityTarget
	var current bool
	if j.Queue != "integrity" || j.Kind != "artifact.integrity" || len(j.Target) > 8192 || json.Unmarshal(j.Target, &target) != nil || target.Validate() != nil {
		return target, false, ErrConflict
	}
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND digest=$2 AND size=$3)`, target.Repository, target.Digest, target.Size).Scan(&current)
	})
	return target, current, e
}
func (s *Store) finishJob(ctx context.Context, i WorkerIdentity, j Job, apply func(pgx.Tx) (string, string, error)) (string, error) {
	outcome := ""
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		code := ""
		outcome = "cancelled"
		if state != "cancel_requested" {
			outcome, code, e = apply(tx)
			if e != nil {
				return e
			}
		}
		var delay int
		if outcome == "retry" {
			p, e := queuePolicy(ctx, tx, i.Tenant, j.Queue)
			if e != nil {
				return e
			}
			if j.CycleAttempts >= p.MaxAttempts {
				outcome = "failed"
			} else {
				delay = p.RetrySeconds
				for n := 1; n < j.CycleAttempts && delay < p.RetryMaxSeconds; n++ {
					delay = min(p.RetryMaxSeconds, delay*2)
				}
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.jobs SET state=$1,last_error=$2,lease_token='',lease_until='epoch',available_at=clock_timestamp()+make_interval(secs=>$3),finished_at=CASE WHEN $1='retry' THEN NULL ELSE clock_timestamp() END,updated_at=clock_timestamp() WHERE sequence=$4 AND task=$5`, outcome, code, delay, j.Sequence, j.Task); e != nil {
			return e
		}
		j.State = outcome
		return jobAudit(ctx, tx, i, "job."+outcome, j)
	})
	return outcome, e
}
func (s *Store) FinishEvent(ctx context.Context, i WorkerIdentity, j Job, p EventProjection) (string, error) {
	return s.finishJob(ctx, i, j, func(tx pgx.Tx) (string, string, error) {
		if j.Queue != "events" || p.Sequence != j.Sequence || p.Kind != j.Kind {
			return "", "", ErrConflict
		}
		var hash string
		if e := tx.QueryRow(ctx, `SELECT hash FROM cratectl.events WHERE sequence=$1`, j.Sequence).Scan(&hash); e != nil {
			return "", "", e
		}
		if hash != p.Hash {
			return "", "", ErrConflict
		}
		position, e := nextEventSequence(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"})
		if e != nil {
			return "", "", e
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.event_projections(tenant,sequence,event_hash,actor,kind,repository,path,digest,position) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, i.Tenant, p.Sequence, p.Hash, p.Actor, p.Kind, p.Repository, p.Path, p.Digest, position); e != nil {
			return "", "", e
		}
		return "succeeded", "", nil
	})
}
func (s *Store) FinishIntegrity(ctx context.Context, i WorkerIdentity, j Job, status string) (string, error) {
	switch status {
	case "verified", "missing", "corrupt", "superseded", "io_error", "limit", "timeout":
	default:
		return "", ErrConflict
	}
	var target IntegrityTarget
	if j.Queue != "integrity" || j.Kind != "artifact.integrity" || json.Unmarshal(j.Target, &target) != nil || target.Validate() != nil {
		return "", ErrConflict
	}
	return s.finishJob(ctx, i, j, func(tx pgx.Tx) (string, string, error) {
		var current bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND digest=$2 AND size=$3)`, target.Repository, target.Digest, target.Size).Scan(&current); e != nil {
			return "", "", e
		}
		if !current {
			status = "superseded"
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.integrity_observations(tenant,sequence,task,generation,repository,digest,size,status,worker) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, i.Tenant, j.Sequence, j.Task, j.Generation, target.Repository, target.Digest, target.Size, status, j.Worker); e != nil {
			return "", "", e
		}
		if status == "verified" || status == "superseded" {
			return "succeeded", "", nil
		}
		if status == "limit" {
			return "failed", "object_budget", nil
		}
		return "retry", "integrity_" + status, nil
	})
}
func (s *Store) FailJob(ctx context.Context, i WorkerIdentity, j Job, code string, permanent bool) (string, error) {
	switch code {
	case "retention_requester_authorization", "retention_plan_changed", "retention_schedule_changed":
		if j.Kind != "repository.retention" {
			return "", ErrConflict
		}
	case "invalid_event", "invalid_target", "event_budget", "worker_stopped", "handler_timeout", "handler_failure", "inventory_budget", "storage_changed", "unsupported_storage":
	case "repair_attempt_unconfirmed", "repair_requester_authorization", "repair_target_changed", "repair_storage_changed", "repair_unsupported_storage", "repair_source_integrity", "repair_object_limit", "repair_invalid_intent", "repair_cancelled", "repair_completion_authority_changed", "repair_reference_conflict":
		if j.Kind != "storage.repair" {
			return "", ErrConflict
		}
	default:
		return "", ErrConflict
	}
	return s.finishJob(ctx, i, j, func(pgx.Tx) (string, string, error) {
		if permanent {
			return "failed", code, nil
		}
		return "retry", code, nil
	})
}
func (s *Store) WorkerJob(ctx context.Context, i WorkerIdentity, sequence int64, task string) (Job, error) {
	var j Job
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		return scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, sequence, task), &j)
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	j.Token = ""
	return j, e
}
