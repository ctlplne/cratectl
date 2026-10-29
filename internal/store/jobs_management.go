// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func validJobState(s string) bool {
	switch s {
	case "", "pending", "retry", "running", "cancel_requested", "succeeded", "failed", "cancelled", "uncertain":
		return true
	}
	return false
}
func (s *Store) Jobs(ctx context.Context, i Identity, queue, state, after string, limit int) ([]Job, string, error) {
	out := []Job{}
	next := ""
	var seq int64
	task := ""
	if i.Role != "admin" {
		return out, next, ErrDenied
	}
	if limit < 1 || limit > 1000 || queue != "" && !QueueName(queue) || !validJobState(state) {
		return out, next, ErrConflict
	}
	if after != "" {
		var e error
		seq, task, e = ParseJobID(after)
		if e != nil {
			return out, next, e
		}
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE ($1='' OR queue=$1) AND ($2='' OR state=$2) AND (sequence,task)>($3,$4) ORDER BY sequence,task LIMIT $5`, queue, state, seq, task, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var j Job
			if e = scanJob(rows, &j); e != nil {
				return e
			}
			j.Token = ""
			out = append(out, j)
		}
		return rows.Err()
	})
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID()
	}
	return out, next, e
}
func (s *Store) Job(ctx context.Context, i Identity, id string) (Job, error) {
	var j Job
	if i.Role != "admin" {
		return j, ErrDenied
	}
	seq, task, e := ParseJobID(id)
	if e != nil {
		return j, e
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		return scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE sequence=$1 AND task=$2`, seq, task), &j)
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	j.Token = ""
	return j, e
}

type QueueStatus struct {
	QueuePolicy
	Outstanding int `json:"outstanding"`
	Running     int `json:"running"`
}

func (s *Store) Queues(ctx context.Context, i Identity) ([]QueueStatus, error) {
	out := []QueueStatus{}
	if i.Role != "admin" {
		return out, ErrDenied
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		for _, queue := range []string{"events", "integrity"} {
			p := QueueStatus{QueuePolicy: QueuePolicy{Queue: queue, Capacity: 100000, MaxRunning: 2, MaxAttempts: 5, RetrySeconds: 5, RetryMaxSeconds: 300}}
			e := tx.QueryRow(ctx, `SELECT capacity,max_running,max_attempts,retry_seconds,retry_max_seconds FROM cratectl.queue_policies WHERE queue=$1`, queue).Scan(&p.Capacity, &p.MaxRunning, &p.MaxAttempts, &p.RetrySeconds, &p.RetryMaxSeconds)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if e = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state NOT IN ('succeeded','failed','cancelled')),count(*) FILTER(WHERE state IN ('running','cancel_requested') AND lease_until>clock_timestamp()) FROM cratectl.jobs WHERE queue=$1`, queue).Scan(&p.Outstanding, &p.Running); e != nil {
				return e
			}
			out = append(out, p)
		}
		return nil
	})
	return out, e
}
func (s *Store) SetQueuePolicy(ctx context.Context, i Identity, key, fingerprint string, p QueuePolicy) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if e := p.Validate(); e != nil {
		return Result{}, e
	}
	return s.mutateIntent(ctx, i, key, fingerprint, "queue.policy.changed", false, func(tx pgx.Tx) (any, int, error) {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.queue_policies(tenant,queue,capacity,max_running,max_attempts,retry_seconds,retry_max_seconds) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant,queue) DO UPDATE SET capacity=excluded.capacity,max_running=excluded.max_running,max_attempts=excluded.max_attempts,retry_seconds=excluded.retry_seconds,retry_max_seconds=excluded.retry_max_seconds`, i.Tenant, p.Queue, p.Capacity, p.MaxRunning, p.MaxAttempts, p.RetrySeconds, p.RetryMaxSeconds)
		return p, 200, e
	})
}
func (s *Store) ControlJob(ctx context.Context, i Identity, key, fingerprint, id, action string, ackUnknown bool) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	seq, task, e := ParseJobID(id)
	if e != nil {
		return Result{}, e
	}
	if action != "retry" && action != "cancel" {
		return Result{}, ErrConflict
	}
	return s.mutateIntent(ctx, i, key, fingerprint, "job."+action+".requested", false, func(tx pgx.Tx) (any, int, error) {
		var j Job
		e := scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE sequence=$1 AND task=$2 FOR UPDATE`, seq, task), &j)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		if e != nil {
			return nil, 0, e
		}
		if action == "retry" {
			if j.State != "failed" && j.State != "succeeded" && j.State != "cancelled" && j.State != "uncertain" || j.State == "uncertain" && !ackUnknown {
				return nil, 0, ErrConflict
			}
			p, e := queuePolicy(ctx, tx, i.Tenant, j.Queue)
			if e != nil {
				return nil, 0, e
			}
			if e = queueRoom(ctx, tx, p, 1); e != nil {
				return nil, 0, e
			}
			e = scanJob(tx.QueryRow(ctx, `UPDATE cratectl.jobs SET state='retry',generation=generation+1,cycle_attempts=0,available_at=clock_timestamp(),lease_until='epoch',lease_token='',last_error='',finished_at=NULL,updated_at=clock_timestamp() WHERE sequence=$1 AND task=$2 RETURNING `+jobColumns, seq, task), &j)
		} else {
			switch j.State {
			case "pending", "retry":
				e = scanJob(tx.QueryRow(ctx, `UPDATE cratectl.jobs SET state='cancelled',generation=generation+1,lease_until='epoch',lease_token='',last_error='cancelled',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE sequence=$1 AND task=$2 RETURNING `+jobColumns, seq, task), &j)
			case "running":
				e = scanJob(tx.QueryRow(ctx, `UPDATE cratectl.jobs SET state='cancel_requested',updated_at=clock_timestamp() WHERE sequence=$1 AND task=$2 RETURNING `+jobColumns, seq, task), &j)
			case "cancel_requested", "cancelled":
			default:
				return nil, 0, ErrConflict
			}
		}
		j.Token = ""
		return j, 200, e
	})
}

type IntegrityObservation struct {
	Sequence   int64     `json:"sequence"`
	Task       string    `json:"task"`
	Generation int64     `json:"generation"`
	Repository string    `json:"repository"`
	Digest     string    `json:"digest"`
	Size       int64     `json:"size"`
	Status     string    `json:"status"`
	Worker     string    `json:"worker"`
	Engine     string    `json:"engine"`
	ObservedAt time.Time `json:"observed_at"`
}

func (s *Store) JobObservations(ctx context.Context, i Identity, id string, after int64, limit int) ([]IntegrityObservation, bool, error) {
	out := []IntegrityObservation{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	seq, task, e := ParseJobID(id)
	if e != nil {
		return out, false, e
	}
	if after < 0 || limit < 1 || limit > 1000 {
		return out, false, ErrConflict
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT sequence,task,generation,repository,digest,size,status,worker,engine,observed_at FROM cratectl.integrity_observations WHERE sequence=$1 AND task=$2 AND generation>$3 ORDER BY generation LIMIT $4`, seq, task, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v IntegrityObservation
			if e = rows.Scan(&v.Sequence, &v.Task, &v.Generation, &v.Repository, &v.Digest, &v.Size, &v.Status, &v.Worker, &v.Engine, &v.ObservedAt); e != nil {
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
func (s *Store) Activity(ctx context.Context, i Identity, after int64, limit int) ([]EventProjection, bool, error) {
	out := []EventProjection{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if after < 0 || limit < 1 || limit > 1000 {
		return out, false, ErrConflict
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT sequence,event_hash,actor,kind,repository,path,digest,position FROM cratectl.event_projections WHERE position>$1 ORDER BY position LIMIT $2`, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p EventProjection
			if e = rows.Scan(&p.Sequence, &p.Hash, &p.Actor, &p.Kind, &p.Repository, &p.Path, &p.Digest, &p.Position); e != nil {
				return e
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
