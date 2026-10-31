// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

func (s *Store) RetentionPolicies(ctx context.Context, i Identity, repo, after string, limit int) ([]RetentionPolicy, bool, error) {
	out := []RetentionPolicy{}
	if limit < 1 || limit > 100 || after != "" && !Name.MatchString(after) {
		return out, false, ErrRetentionInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := retentionRepositoryRecord(ctx, tx, i, repo); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT configuration FROM cratectl.retention_policies WHERE repository=$1 AND name>$2 ORDER BY name LIMIT $3`, repo, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p RetentionPolicy
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if len(raw) > 16384 || json.Unmarshal(raw, &p) != nil || p.RetentionSettings.Validate() != nil {
				return ErrRetentionInput
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
func (s *Store) RetentionHistory(ctx context.Context, i Identity, repo, name string, after int64, limit int) ([]RetentionPolicy, bool, error) {
	out := []RetentionPolicy{}
	if limit < 1 || limit > 100 || after < 0 {
		return out, false, ErrRetentionInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := retentionRepositoryRecord(ctx, tx, i, repo); e != nil {
			return e
		}
		if _, e := retentionPolicy(ctx, tx, repo, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT configuration FROM cratectl.retention_revisions WHERE repository=$1 AND name=$2 AND revision>$3 ORDER BY revision LIMIT $4`, repo, name, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p RetentionPolicy
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if len(raw) > 16384 || json.Unmarshal(raw, &p) != nil || p.RetentionSettings.Validate() != nil {
				return ErrRetentionInput
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

type RetentionRunSummary struct {
	Job   string        `json:"job"`
	State string        `json:"state"`
	Plan  RetentionPlan `json:"plan"`
}

func (s *Store) RetentionRuns(ctx context.Context, i Identity, repo, name string, after int64, limit int) ([]RetentionRunSummary, bool, error) {
	out := []RetentionRunSummary{}
	if limit < 1 || limit > 100 || after < 0 {
		return out, false, ErrRetentionInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := retentionRepositoryRecord(ctx, tx, i, repo); e != nil {
			return e
		}
		if _, e := retentionPolicy(ctx, tx, repo, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT r.sequence,r.task,j.state,r.plan FROM cratectl.retention_runs r JOIN cratectl.jobs j ON(j.tenant,j.sequence,j.task)=(r.tenant,r.sequence,r.task) WHERE r.repository=$1 AND r.name=$2 AND r.sequence>$3 ORDER BY r.sequence LIMIT $4`, repo, name, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p RetentionRunSummary
			var seq int64
			var task string
			var raw []byte
			if e = rows.Scan(&seq, &task, &p.State, &raw); e != nil {
				return e
			}
			if len(raw) > 16384 || json.Unmarshal(raw, &p.Plan) != nil {
				return ErrRetentionInput
			}
			p.Job = (Job{Sequence: seq, Task: task}).ID()
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
