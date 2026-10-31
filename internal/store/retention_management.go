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
		var e error
		out, e = retentionRunSummaries(ctx, tx, i, repo, name, after, limit, false)
		return e
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}

func retentionRunSummaries(ctx context.Context, tx pgx.Tx, i Identity, repo, name string, after int64, limit int, scheduled bool) ([]RetentionRunSummary, error) {
	out := []RetentionRunSummary{}
	rows, e := tx.Query(ctx, `SELECT r.sequence,r.task,j.state FROM cratectl.retention_runs r JOIN cratectl.jobs j ON(j.tenant,j.sequence,j.task)=(r.tenant,r.sequence,r.task) WHERE r.repository=$1 AND r.name=$2 AND r.sequence>$3 AND(NOT $5::boolean OR EXISTS(SELECT 1 FROM cratectl.retention_schedule_runs sr WHERE(sr.tenant,sr.sequence,sr.task)=(r.tenant,r.sequence,r.task))) ORDER BY r.sequence LIMIT $4`, repo, name, after, limit+1, scheduled)
	if e != nil {
		return out, e
	}
	type reference struct {
		sequence    int64
		task, state string
	}
	refs := []reference{}
	for rows.Next() {
		var v reference
		if e = rows.Scan(&v.sequence, &v.task, &v.state); e != nil {
			rows.Close()
			return out, e
		}
		refs = append(refs, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	for _, v := range refs {
		j := Job{Sequence: v.sequence, Task: v.task, Queue: "maintenance", Kind: "repository.retention"}
		plan, _, e := retentionIntent(ctx, tx, i.Tenant, j)
		if e != nil {
			return out, e
		}
		out = append(out, RetentionRunSummary{Job: j.ID(), State: v.state, Plan: plan})
	}
	return out, nil
}
