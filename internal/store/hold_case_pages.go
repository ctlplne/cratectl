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

type HoldCaseListRequest struct {
	ListRequest
	State, Repository, Path, CaseID string
}
type HoldCaseRecord struct {
	HoldCase
	Status          string `json:"status"`
	RepositoryState string `json:"repository_state"`
}
type HoldCaseChange struct {
	Sequence   int64         `json:"sequence"`
	Action     string        `json:"action"`
	Case       HoldCase      `json:"case"`
	Current    ArtifactState `json:"current"`
	Actor      string        `json:"actor"`
	RecordedAt time.Time     `json:"recorded_at"`
	EventHash  string        `json:"event_hash"`
}

func holdCasePagePosition(req ListRequest) (int64, error) {
	if req.Validate() != nil || req.Limit > 100 || req.Summary {
		return 0, ErrConflict
	}
	if req.Key == "" {
		return 0, nil
	}
	n, e := strconv.ParseInt(req.Key, 10, 64)
	if e != nil || n < 1 {
		return 0, ErrConflict
	}
	return n, nil
}
func (req HoldCaseListRequest) Validate() error {
	if _, e := holdCasePagePosition(req.ListRequest); e != nil {
		return e
	}
	if req.Repository != "" && !Name.MatchString(req.Repository) || req.Path != "" && !validHoldPath(req.Path) || req.CaseID != "" && !validCaseID(req.CaseID) {
		return ErrConflict
	}
	switch req.State {
	case "", "active", "expired", "released", "all":
		return nil
	}
	return ErrConflict
}

// Creation sequence is immutable and tenant-unique, so changing or releasing a
// case does not move it across a continuation. Cursors carry no package paths.
func (s *Store) HoldCasePage(ctx context.Context, i Identity, req HoldCaseListRequest) ([]HoldCaseRecord, ListWindow, time.Time, error) {
	out := []HoldCaseRecord{}
	window := ListWindow{}
	var observed time.Time
	if i.Role != "admin" {
		return out, window, observed, ErrDenied
	}
	if req.Validate() != nil {
		return out, window, observed, ErrConflict
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
		if e := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+strings.ReplaceAll(holdCaseColumns, "clock_timestamp()", "$1")+`,COALESCE(rl.state,'active')
 FROM cratectl.artifact_hold_cases c LEFT JOIN cratectl.repository_lifecycle rl ON (rl.tenant,rl.repository)=(c.tenant,c.repository)
 WHERE ($2='' OR c.repository=$2) AND ($3='' OR c.path=$3) AND ($4='' OR c.case_id=$4)
 AND ($5='all' OR $5='released' AND c.released OR $5='expired' AND NOT c.released AND c.hold_until<=$1
 OR $5='active' AND NOT c.released AND (c.hold_until IS NULL OR c.hold_until>$1))
 AND c.created_sequence `+compare+` $6
 AND (c.repository||' '||c.path||' '||c.digest||' '||c.case_id||' '||c.hold_reason||' '||c.reason) COLLATE "C" ~ $7
 ORDER BY c.created_sequence `+order+` LIMIT $8`, observed, req.Repository, req.Path, req.CaseID, state, position, literalSearch(req.Query), req.Limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		size := 0
		actual := req.ListRequest
		for rows.Next() {
			var v HoldCaseRecord
			c := &v.HoldCase
			if e = rows.Scan(&c.Repository, &c.Path, &c.Digest, &c.CaseID, &c.Revision, &c.Held, &c.Released, &c.HoldReason, &c.HoldUntil, &c.Reason, &c.Actor, &c.ChangedAt, &c.CreatedSequence, &c.ChangeSequence, &v.RepositoryState); e != nil {
				return e
			}
			v.Status = "expired"
			if c.Released {
				v.Status = "released"
			} else if c.Held {
				v.Status = "active"
			}
			raw, e := json.Marshal(v)
			if e != nil {
				return e
			}
			size += len(raw)
			if size > req.metadataBudget() && len(out) == 0 {
				return ErrMetadataLimit
			}
			out = append(out, v)
			if size > req.metadataBudget() {
				actual.Limit = len(out) - 1
				break
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		out, window = trimPage(out, actual, func(v HoldCaseRecord) string { return strconv.FormatInt(v.CreatedSequence, 10) })
		return nil
	})
	return out, window, observed, e
}

const holdCaseEventPredicate = `(e.payload::jsonb->>'kind')='artifact.hold_case.changed'`

func (s *Store) HoldCaseHistory(ctx context.Context, i Identity, repo, path, id string, req ListRequest) ([]HoldCaseChange, ListWindow, error) {
	out := []HoldCaseChange{}
	window := ListWindow{}
	if i.Role != "admin" {
		return out, window, ErrDenied
	}
	position, e := holdCasePagePosition(req)
	if e != nil || req.Query != "" {
		return out, window, ErrConflict
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := authorizeHoldCase(ctx, tx, i, repo, path, id); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT e.sequence,e.payload::jsonb#>>'{data,action}',
 (e.payload::jsonb#>'{data,case}')::text,(e.payload::jsonb#>'{data,current}')::text,
 e.payload::jsonb->>'actor',e.created_at,e.hash FROM cratectl.events e WHERE `+holdCaseEventPredicate+`
 AND (e.payload::jsonb#>>'{data,case,repository}')=$1 AND (e.payload::jsonb#>>'{data,case,path}')=$2
 AND (e.payload::jsonb#>>'{data,case,case_id}')=$3 AND e.sequence `+compare+` $4 ORDER BY e.sequence `+order+` LIMIT $5`, repo, path, id, position, req.Limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		size := 0
		actual := req
		for rows.Next() {
			var v HoldCaseChange
			var c, current []byte
			if e = rows.Scan(&v.Sequence, &v.Action, &c, &current, &v.Actor, &v.RecordedAt, &v.EventHash); e != nil {
				return e
			}
			if json.Unmarshal(c, &v.Case) != nil || json.Unmarshal(current, &v.Current) != nil {
				return ErrConflict
			}
			raw, e := json.Marshal(v)
			if e != nil {
				return e
			}
			size += len(raw)
			if size > req.metadataBudget() && len(out) == 0 {
				return ErrMetadataLimit
			}
			out = append(out, v)
			if size > req.metadataBudget() {
				actual.Limit = len(out) - 1
				break
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		out, window = trimPage(out, actual, func(v HoldCaseChange) string { return strconv.FormatInt(v.Sequence, 10) })
		return nil
	})
	return out, window, e
}
