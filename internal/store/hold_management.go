// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// HoldListRequest uses an encrypted global repository/path position. Other
// management endpoints retain their existing 2,048-byte position limit.
type HoldListRequest struct {
	ListRequest
	State, Repository string
}
type HoldRecord struct {
	ArtifactState
	Status          string `json:"status"`
	RepositoryState string `json:"repository_state"`
	Format          string `json:"format"`
	Mode            string `json:"mode"`
}
type HoldChange struct {
	Sequence   int64         `json:"sequence"`
	Action     string        `json:"action"`
	State      ArtifactState `json:"state"`
	Actor      string        `json:"actor"`
	RecordedAt time.Time     `json:"recorded_at"`
	EventHash  string        `json:"event_hash"`
}

func (req HoldListRequest) Validate() error {
	copy := req.ListRequest
	copy.Key = ""
	copy.Before = false
	if copy.Validate() != nil || req.Limit > 100 || req.Summary || req.Before && req.Key == "" || req.Repository != "" && !Name.MatchString(req.Repository) {
		return ErrConflict
	}
	switch req.State {
	case "", "active", "expired", "released", "all":
	default:
		return ErrConflict
	}
	if req.Key != "" {
		bits := strings.Split(req.Key, "\n")
		if len(bits) != 2 || !Name.MatchString(bits[0]) || len(bits[1]) > 2048 || !validHoldPath(bits[1]) {
			return ErrConflict
		}
	}
	return nil
}
func validHoldPath(path string) bool {
	return len(path) > 0 && len(path) <= 2048 && utf8.ValidString(path) && strings.IndexFunc(path, unicode.IsControl) < 0 && lifecycleOCIPath(path)
}
func holdPosition(state ArtifactState) string { return state.Repository + "\n" + state.Path }

const holdEventPredicate = `(e.payload::jsonb->>'kind')='artifact.lifecycle.changed' AND (e.payload::jsonb#>>'{data,action}') IN ('hold','release_hold')`

// HoldPage reads current observations and actual prior receipts. A native delete
// without any hold receipt is not mislabeled as a released hold.
func (s *Store) HoldPage(ctx context.Context, i Identity, req HoldListRequest) ([]HoldRecord, ListWindow, time.Time, error) {
	out := []HoldRecord{}
	window := ListWindow{}
	var observed time.Time
	if i.Role != "admin" {
		return out, window, observed, ErrDenied
	}
	if req.Validate() != nil {
		return out, window, observed, ErrConflict
	}
	state := req.State
	if state == "" {
		state = "active"
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT l.repository,l.path,l.digest,l.deleted,
   l.hold_reason<>'' AND (l.hold_until IS NULL OR l.hold_until>$1),
   l.revision,l.hold_reason,l.hold_until,l.reason,l.actor,l.changed_at,l.change_sequence,
   COALESCE(rl.state,'active'),r.format,r.mode,
   EXISTS(SELECT 1 FROM cratectl.artifact_hold_cases c WHERE (c.tenant,c.repository,c.path)=(l.tenant,l.repository,l.path) AND NOT c.released AND (c.hold_until IS NULL OR c.hold_until>$1)),
   EXISTS(SELECT 1 FROM cratectl.hold_matter_members m WHERE (m.tenant,m.repository,m.path)=(l.tenant,l.repository,l.path) AND NOT m.released AND (m.hold_until IS NULL OR m.hold_until>$1))
   FROM cratectl.artifact_lifecycle l
   JOIN cratectl.repositories r ON (r.tenant,r.name)=(l.tenant,l.repository)
   LEFT JOIN cratectl.repository_lifecycle rl ON (rl.tenant,rl.repository)=(l.tenant,l.repository)
   WHERE ($2='' OR l.repository=$2)
   AND (l.hold_reason<>'' OR EXISTS(SELECT 1 FROM cratectl.events e
     WHERE e.tenant=l.tenant AND `+holdEventPredicate+`
     AND (e.payload::jsonb#>>'{data,current,repository}')=l.repository
     AND (e.payload::jsonb#>>'{data,current,path}')=l.path))
   AND ($3='all' OR $3='active' AND l.hold_reason<>'' AND (l.hold_until IS NULL OR l.hold_until>$1)
     OR $3='expired' AND l.hold_reason<>'' AND l.hold_until<=$1
     OR $3='released' AND l.hold_reason='')
   AND (l.repository||E'\n'||l.path) COLLATE "C" `+compare+` $4 COLLATE "C"
   AND (l.repository||' '||l.path||' '||l.digest||' '||l.hold_reason||' '||l.reason) COLLATE "C" ~ $5
   ORDER BY (l.repository||E'\n'||l.path) COLLATE "C" `+order+` LIMIT $6`,
			observed, req.Repository, state, req.Key, literalSearch(req.Query), req.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		bytes := 0
		actual := req.ListRequest
		for rows.Next() {
			var v HoldRecord
			if err = rows.Scan(&v.Repository, &v.Path, &v.Digest, &v.Deleted, &v.LegacyHeld, &v.Revision, &v.HoldReason, &v.HoldUntil, &v.Reason, &v.Actor, &v.ChangedAt, &v.ChangeSequence, &v.RepositoryState, &v.Format, &v.Mode, &v.CaseHeld, &v.MatterHeld); err != nil {
				return err
			}
			v.Status = "released"
			if v.HoldReason != "" {
				v.Status = "expired"
				if v.LegacyHeld {
					v.Status = "active"
				}
			}
			v.Held = v.LegacyHeld || v.CaseHeld || v.MatterHeld
			raw, err := json.Marshal(v)
			if err != nil {
				return err
			}
			bytes += len(raw)
			if bytes > req.metadataBudget() && len(out) == 0 {
				return ErrMetadataLimit
			}
			out = append(out, v)
			if bytes > req.metadataBudget() {
				actual.Limit = len(out) - 1
				break
			}
		}
		if err = rows.Err(); err != nil {
			return err
		}
		out, window = trimPage(out, actual, func(v HoldRecord) string { return holdPosition(v.ArtifactState) })
		return nil
	})
	return out, window, observed, err
}
func (s *Store) HoldHistory(ctx context.Context, i Identity, repo, path string, req ListRequest) ([]HoldChange, ListWindow, error) {
	out := []HoldChange{}
	window := ListWindow{}
	if i.Role != "admin" {
		return out, window, ErrDenied
	}
	if req.Validate() != nil || req.Limit > 100 || req.Query != "" || req.Summary || !Name.MatchString(repo) || !validHoldPath(path) {
		return out, window, ErrConflict
	}
	var position int64
	var err error
	if req.Key != "" {
		position, err = strconv.ParseInt(req.Key, 10, 64)
		if err != nil || position < 0 {
			return out, window, ErrConflict
		}
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, err := artifactLifecycleRecordRetained(ctx, tx, i, repo, path); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT e.sequence,e.payload::jsonb#>>'{data,action}',
   (e.payload::jsonb#>'{data,current}')::text,e.payload::jsonb->>'actor',e.created_at,e.hash
   FROM cratectl.events e WHERE `+holdEventPredicate+`
   AND (e.payload::jsonb#>>'{data,current,repository}')=$1
   AND (e.payload::jsonb#>>'{data,current,path}')=$2
   AND e.sequence `+compare+` $3 ORDER BY e.sequence `+order+` LIMIT $4`, repo, path, position, req.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		bytes := 0
		actual := req
		for rows.Next() {
			var v HoldChange
			var raw []byte
			if err = rows.Scan(&v.Sequence, &v.Action, &raw, &v.Actor, &v.RecordedAt, &v.EventHash); err != nil {
				return err
			}
			if len(raw) > 16<<10 || json.Unmarshal(raw, &v.State) != nil || v.State.Repository != repo || v.State.Path != path || v.State.Revision < 1 || v.State.ChangeSequence != v.Sequence {
				return ErrConflict
			}
			bytes += len(raw) + len(v.Actor) + len(v.Action) + len(v.EventHash) + 64
			if bytes > req.metadataBudget() && len(out) == 0 {
				return ErrMetadataLimit
			}
			out = append(out, v)
			if bytes > req.metadataBudget() {
				actual.Limit = len(out) - 1
				break
			}
		}
		if err = rows.Err(); err != nil {
			return err
		}
		out, window = trimPage(out, actual, func(v HoldChange) string { return strconv.FormatInt(v.Sequence, 10) })
		return nil
	})
	return out, window, err
}
