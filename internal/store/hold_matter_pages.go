// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func readMatterRows[T any](rows pgx.Rows, req ListRequest, scan func(pgx.Row) (T, error), key func(T) string) ([]T, ListWindow, error) {
	out := []T{}
	defer rows.Close()
	size := 0
	actual := req
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			return nil, ListWindow{}, e
		}
		raw, e := json.Marshal(v)
		if e != nil {
			return nil, ListWindow{}, e
		}
		size += len(raw)
		if size > req.metadataBudget() && len(out) == 0 {
			return nil, ListWindow{}, ErrMetadataLimit
		}
		out = append(out, v)
		if size > req.metadataBudget() {
			actual.Limit = len(out) - 1
			break
		}
	}
	if e := rows.Err(); e != nil {
		return nil, ListWindow{}, e
	}
	out, w := trimPage(out, actual, key)
	return out, w, nil
}
func (s *Store) MatterPage(ctx context.Context, i Identity, req ListRequest) ([]HoldMatter, ListWindow, error) {
	out := []HoldMatter{}
	w := ListWindow{}
	if i.Role != "admin" {
		return out, w, ErrDenied
	}
	if req.Validate() != nil || req.Limit > 100 || req.Summary || req.Key != "" && !Name.MatchString(req.Key) {
		return out, w, ErrMatterInput
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+matterColumns+` FROM cratectl.hold_matters WHERE name COLLATE "C" `+compare+` $1 COLLATE "C" AND (name||' '||title||' '||state||' '||reason) COLLATE "C" ~ $2 ORDER BY name COLLATE "C" `+order+` LIMIT $3`, req.Key, literalSearch(req.Query), req.Limit+1)
		if e != nil {
			return e
		}
		out, w, e = readMatterRows(rows, req, func(row pgx.Row) (HoldMatter, error) { var m HoldMatter; e := scanMatter(row, &m); return m, e }, func(m HoldMatter) string { return m.Name })
		return e
	})
	return out, w, e
}

type MatterMemberPageRequest struct {
	ListRequest
	State, Repository string
}
type MatterMemberRecord struct {
	HoldMatterMember
	Status          string `json:"status"`
	RepositoryState string `json:"repository_state"`
	Deleted         bool   `json:"deleted"`
}

func (req MatterMemberPageRequest) Validate() error {
	if _, e := holdCasePagePosition(req.ListRequest); e != nil {
		return ErrMatterInput
	}
	if req.Repository != "" && !Name.MatchString(req.Repository) {
		return ErrMatterInput
	}
	switch req.State {
	case "", "active", "expired", "released", "all":
		return nil
	}
	return ErrMatterInput
}
func (s *Store) MatterMembers(ctx context.Context, i Identity, name string, req MatterMemberPageRequest) ([]MatterMemberRecord, ListWindow, time.Time, error) {
	out := []MatterMemberRecord{}
	w := ListWindow{}
	var observed time.Time
	if e := matterAdmin(i, name); e != nil {
		return out, w, observed, e
	}
	if e := req.Validate(); e != nil {
		return out, w, observed, e
	}
	position, _ := holdCasePagePosition(req.ListRequest)
	state := req.State
	if state == "" {
		state = "active"
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := matterInTx(ctx, tx, name); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+strings.ReplaceAll(matterMemberColumns, "clock_timestamp()", "$1")+`,COALESCE(rl.state,'active'),COALESCE(l.deleted,false)
 FROM cratectl.hold_matter_members m LEFT JOIN cratectl.repository_lifecycle rl ON(rl.tenant,rl.repository)=(m.tenant,m.repository)
 LEFT JOIN cratectl.artifact_lifecycle l ON(l.tenant,l.repository,l.path)=(m.tenant,m.repository,m.path)
 WHERE m.matter=$2 AND ($3='' OR m.repository=$3)
 AND ($4='all' OR $4='released' AND m.released OR $4='expired' AND NOT m.released AND m.hold_until<=$1 OR $4='active' AND NOT m.released AND(m.hold_until IS NULL OR m.hold_until>$1))
 AND m.created_sequence `+compare+` $5 AND(m.repository||' '||m.path||' '||m.digest||' '||m.hold_reason||' '||m.reason) COLLATE "C" ~ $6
 ORDER BY m.created_sequence `+order+` LIMIT $7`, observed, name, req.Repository, state, position, literalSearch(req.Query), req.Limit+1)
		if e != nil {
			return e
		}
		out, w, e = readMatterRows(rows, req.ListRequest, func(row pgx.Row) (MatterMemberRecord, error) {
			var v MatterMemberRecord
			m := &v.HoldMatterMember
			e := row.Scan(&m.Matter, &m.Repository, &m.Path, &m.Digest, &m.Revision, &m.Held, &m.Released, &m.HoldReason, &m.HoldUntil, &m.Reason, &m.Actor, &m.CreatedSequence, &m.ChangeSequence, &m.ChangedAt, &v.RepositoryState, &v.Deleted)
			v.Status = "expired"
			if m.Released {
				v.Status = "released"
			} else if m.Held {
				v.Status = "active"
			}
			return v, e
		}, func(v MatterMemberRecord) string { return strconv.FormatInt(v.CreatedSequence, 10) })
		return e
	})
	return out, w, observed, e
}
func (s *Store) MatterOperations(ctx context.Context, i Identity, name string, req ListRequest) ([]MatterOperation, ListWindow, error) {
	out := []MatterOperation{}
	w := ListWindow{}
	if e := matterAdmin(i, name); e != nil {
		return out, w, e
	}
	position, e := holdCasePagePosition(req)
	if e != nil || req.Query != "" {
		return out, w, ErrMatterInput
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := matterInTx(ctx, tx, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT sequence FROM cratectl.hold_matter_operations WHERE matter=$1 AND sequence `+compare+` $2 ORDER BY sequence `+order+` LIMIT $3`, name, position, req.Limit+1)
		if e != nil {
			return e
		}
		ids := []int64{}
		for rows.Next() {
			var id int64
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		size := 0
		actual := req
		for _, id := range ids {
			o, e := operationRecord(ctx, tx, i.Tenant, name, id)
			if e != nil {
				return e
			}
			raw, _ := json.Marshal(o.MatterOperation)
			size += len(raw)
			if size > req.metadataBudget() && len(out) == 0 {
				return ErrMetadataLimit
			}
			out = append(out, o.MatterOperation)
			if size > req.metadataBudget() {
				actual.Limit = len(out) - 1
				break
			}
		}
		out, w = trimPage(out, actual, func(o MatterOperation) string { return strconv.FormatInt(o.Sequence, 10) })
		return nil
	})
	return out, w, e
}

type MatterTargetOutcome struct {
	MatterTarget
	Outcome            string     `json:"outcome"`
	MemberRevision     int64      `json:"member_revision"`
	OutcomeRevision    int64      `json:"outcome_revision"`
	EffectiveHeldAfter *bool      `json:"effective_held_after,omitempty"`
	ObservedAt         *time.Time `json:"observed_at,omitempty"`
}

func (s *Store) MatterOperationItems(ctx context.Context, i Identity, name string, sequence int64, req ListRequest) ([]MatterTargetOutcome, ListWindow, error) {
	out := []MatterTargetOutcome{}
	w := ListWindow{}
	if e := matterAdmin(i, name); e != nil {
		return out, w, e
	}
	position, e := holdCasePagePosition(req)
	if e != nil || req.Query != "" || sequence < 1 {
		return out, w, ErrMatterInput
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := operationRecord(ctx, tx, i.Tenant, name, sequence); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT t.target,COALESCE(f.outcome,'pending'),COALESCE(f.member_revision,0),COALESCE(f.lifecycle_revision,0),f.effective_held,f.observed_at FROM cratectl.hold_matter_targets t LEFT JOIN cratectl.hold_matter_outcomes f ON(f.tenant,f.operation,f.ordinal)=(t.tenant,t.operation,t.ordinal) WHERE t.operation=$1 AND t.ordinal `+compare+` $2 ORDER BY t.ordinal `+order+` LIMIT $3`, sequence, position, req.Limit+1)
		if e != nil {
			return e
		}
		out, w, e = readMatterRows(rows, req, func(row pgx.Row) (MatterTargetOutcome, error) {
			var v MatterTargetOutcome
			var raw []byte
			e := row.Scan(&raw, &v.Outcome, &v.MemberRevision, &v.OutcomeRevision, &v.EffectiveHeldAfter, &v.ObservedAt)
			if e != nil {
				return v, e
			}
			if len(raw) > 8192 || json.Unmarshal(raw, &v.MatterTarget) != nil {
				return v, ErrMatterInput
			}
			return v, nil
		}, func(v MatterTargetOutcome) string { return strconv.FormatInt(v.Ordinal, 10) })
		return e
	})
	return out, w, e
}

type MatterChange struct {
	Sequence   int64           `json:"sequence"`
	Kind       string          `json:"kind"`
	Actor      string          `json:"actor"`
	Data       json.RawMessage `json:"data"`
	RecordedAt time.Time       `json:"recorded_at"`
	EventHash  string          `json:"event_hash"`
}

func (s *Store) MatterHistory(ctx context.Context, i Identity, name string, req ListRequest) ([]MatterChange, ListWindow, error) {
	out := []MatterChange{}
	w := ListWindow{}
	if e := matterAdmin(i, name); e != nil {
		return out, w, e
	}
	position, e := holdCasePagePosition(req)
	if e != nil || req.Query != "" {
		return out, w, ErrMatterInput
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := matterInTx(ctx, tx, name); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT sequence,payload::jsonb->>'kind',payload::jsonb->>'actor',CASE WHEN octet_length(payload)<=$4 THEN (payload::jsonb->'data')::text ELSE NULL END,created_at,hash FROM cratectl.events WHERE(payload::jsonb->>'kind') LIKE 'hold.matter.%' AND(payload::jsonb#>>'{data,matter_name}')=$1 AND sequence `+compare+` $2 ORDER BY sequence `+order+` LIMIT $3`, name, position, req.Limit+1, req.metadataBudget())
		if e != nil {
			return e
		}
		out, w, e = readMatterRows(rows, req, func(row pgx.Row) (MatterChange, error) {
			var v MatterChange
			var raw *string
			e := row.Scan(&v.Sequence, &v.Kind, &v.Actor, &raw, &v.RecordedAt, &v.EventHash)
			if e != nil {
				return v, e
			}
			if raw == nil {
				return v, ErrMetadataLimit
			}
			v.Data = json.RawMessage(*raw)
			return v, nil
		}, func(v MatterChange) string { return strconv.FormatInt(v.Sequence, 10) })
		return e
	})
	return out, w, e
}
