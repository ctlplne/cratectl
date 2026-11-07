// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

var ErrDeleted = errors.New("retained artifact reference is deleted")
var ErrHeld = errors.New("retained content has an active hold")
var ErrReferenced = errors.New("retained content has active incoming references")
var ErrRepositorySuspended = errors.New("repository is suspended")
var ErrRepositoryRemoved = errors.New("repository is retained in removed state")
var ErrLifecycleRevision = errors.New("lifecycle revision or content identity changed")

type ArtifactState struct {
	Repository     string     `json:"repository"`
	Path           string     `json:"path"`
	Digest         string     `json:"digest"`
	Deleted        bool       `json:"deleted"`
	Held           bool       `json:"held"`
	LegacyHeld     bool       `json:"legacy_held,omitempty"`
	CaseHeld       bool       `json:"case_held,omitempty"`
	MatterHeld     bool       `json:"matter_held,omitempty"`
	Revision       int64      `json:"revision"`
	HoldReason     string     `json:"hold_reason,omitempty"`
	HoldUntil      *time.Time `json:"hold_until,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	Actor          string     `json:"actor,omitempty"`
	ChangedAt      *time.Time `json:"changed_at,omitempty"`
	ChangeSequence int64      `json:"change_sequence"`
}
type RepositoryState struct {
	Repository     string     `json:"repository"`
	State          string     `json:"state"`
	Revision       int64      `json:"revision"`
	Reason         string     `json:"reason,omitempty"`
	Actor          string     `json:"actor,omitempty"`
	ChangedAt      *time.Time `json:"changed_at,omitempty"`
	ChangeSequence int64      `json:"change_sequence"`
}

func artifactStateInTx(ctx context.Context, tx pgx.Tx, repo, p string) (ArtifactState, error) {
	s := ArtifactState{Repository: repo, Path: p}
	e := tx.QueryRow(ctx, `SELECT digest,deleted,hold_reason<>'' AND (hold_until IS NULL OR hold_until>clock_timestamp()),revision,hold_reason,hold_until,reason,left(actor,257),changed_at,change_sequence,
 EXISTS(SELECT 1 FROM cratectl.artifact_hold_cases c WHERE (c.tenant,c.repository,c.path)=(l.tenant,l.repository,l.path) AND NOT c.released AND (c.hold_until IS NULL OR c.hold_until>clock_timestamp())),
 EXISTS(SELECT 1 FROM cratectl.hold_matter_members m WHERE (m.tenant,m.repository,m.path)=(l.tenant,l.repository,l.path) AND NOT m.released AND (m.hold_until IS NULL OR m.hold_until>clock_timestamp()))
 FROM cratectl.artifact_lifecycle l WHERE repository=$1 AND path=$2`, repo, p).Scan(&s.Digest, &s.Deleted, &s.LegacyHeld, &s.Revision, &s.HoldReason, &s.HoldUntil, &s.Reason, &s.Actor, &s.ChangedAt, &s.ChangeSequence, &s.CaseHeld, &s.MatterHeld)
	s.Held = s.LegacyHeld || s.CaseHeld || s.MatterHeld
	if len(s.Actor) > 256 {
		return ArtifactState{}, ErrMetadataLimit
	}
	if errors.Is(e, pgx.ErrNoRows) {
		return s, nil
	}
	return s, e
}
func repositoryStateInTx(ctx context.Context, tx pgx.Tx, repo string) (RepositoryState, error) {
	s := RepositoryState{Repository: repo, State: "active"}
	e := tx.QueryRow(ctx, `SELECT state,revision,reason,actor,changed_at,change_sequence FROM cratectl.repository_lifecycle WHERE repository=$1`, repo).Scan(&s.State, &s.Revision, &s.Reason, &s.Actor, &s.ChangedAt, &s.ChangeSequence)
	if errors.Is(e, pgx.ErrNoRows) {
		return s, nil
	}
	return s, e
}
func notDeletedInTx(ctx context.Context, tx pgx.Tx, repo, p string) error {
	var deleted bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle WHERE repository=$1 AND path=$2 AND deleted)`, repo, p).Scan(&deleted); e != nil {
		return e
	}
	if deleted {
		return ErrDeleted
	}
	return nil
}
func validLifecycleReason(s string) bool {
	if len(s) > 1024 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type RepositoryStateRequest struct {
	Action           string `json:"action"`
	ExpectedRevision int64  `json:"expected_revision"`
	Reason           string `json:"reason"`
	DryRun           bool   `json:"dry_run"`
}
type RepositoryStatePreview struct {
	Current       RepositoryState `json:"current"`
	Desired       string          `json:"desired"`
	Retrievals    int             `json:"active_retrievals"`
	Uploads       int             `json:"active_uploads"`
	Groups        []string        `json:"groups"`
	RetainedBytes bool            `json:"retained_bytes"`
	DryRun        bool            `json:"dry_run"`
}

func repositoryStatePreview(ctx context.Context, tx pgx.Tx, i Identity, repo string, input RepositoryStateRequest, budget int) (RepositoryStatePreview, []string, []string, error) {
	out := RepositoryStatePreview{Groups: []string{}, RetainedBytes: true, DryRun: input.DryRun}
	if i.Role != "admin" {
		return out, nil, nil, ErrDenied
	}
	if budget < 1 || budget > 1000000 || input.ExpectedRevision < 0 || !validLifecycleReason(input.Reason) {
		return out, nil, nil, ErrConflict
	}
	if _, e := repositoryRecordInTx(ctx, tx, i, repo, "write"); e != nil {
		return out, nil, nil, e
	}
	current, e := repositoryStateInTx(ctx, tx, repo)
	if e != nil {
		return out, nil, nil, e
	}
	out.Current = current
	if current.Revision != input.ExpectedRevision {
		return out, nil, nil, ErrLifecycleRevision
	}
	switch input.Action {
	case "suspend":
		if current.State == "removed" {
			return out, nil, nil, ErrConflict
		}
		out.Desired = "suspended"
	case "resume":
		if current.State == "removed" {
			return out, nil, nil, ErrConflict
		}
		out.Desired = "active"
	case "remove":
		out.Desired = "removed"
	case "restore":
		if current.State != "removed" {
			return out, nil, nil, ErrConflict
		}
		out.Desired = "active"
	default:
		return out, nil, nil, ErrConflict
	}
	remainingBytes := 8 << 20
	query := func(sql string) ([]string, error) {
		rows, e := tx.Query(ctx, sql, repo, budget+1)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		values := []string{}
		for rows.Next() {
			var v string
			if e = rows.Scan(&v); e != nil {
				return nil, e
			}
			if len(values) >= budget || len(v) > 2048 || len(v) > remainingBytes {
				return nil, ErrMetadataLimit
			}
			remainingBytes -= len(v)
			values = append(values, v)
		}
		return values, rows.Err()
	}
	retrievals, e := query(`SELECT path FROM cratectl.retrievals WHERE repository=$1 AND state='fetching' AND lease_until>clock_timestamp() ORDER BY path LIMIT $2`)
	if e != nil {
		return out, nil, nil, e
	}
	uploads, e := query(`SELECT id FROM cratectl.uploads WHERE repository=$1 AND state='active' AND expires_at>clock_timestamp() ORDER BY id LIMIT $2`)
	if e != nil {
		return out, nil, nil, e
	}
	groups, e := query(`SELECT name FROM cratectl.repositories WHERE mode='group' AND settings->'members' ? $1 ORDER BY name LIMIT $2`)
	if e != nil {
		return out, nil, nil, e
	}
	out.Retrievals, out.Uploads, out.Groups = len(retrievals), len(uploads), groups
	return out, retrievals, uploads, nil
}
func (s *Store) RepositoryState(ctx context.Context, i Identity, repo string) (RepositoryState, error) {
	var state RepositoryState
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		if _, e := repositoryRecordInTx(ctx, tx, i, repo, "read"); e != nil {
			return e
		}
		var e error
		state, e = repositoryStateInTx(ctx, tx, repo)
		return e
	})
	return state, e
}
func (s *Store) ChangeRepositoryState(ctx context.Context, i Identity, repo, key, fp string, input RepositoryStateRequest, budget int) (Result, error) {
	if input.DryRun {
		var out RepositoryStatePreview
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			var e error
			out, _, _, e = repositoryStatePreview(ctx, tx, i, repo, input, budget)
			return e
		})
		return jsonResult(out, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "repository.lifecycle.changed", true, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		_, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
		return e
	}, func(tx pgx.Tx) (any, int, error) {
		out, retrievals, uploads, e := repositoryStatePreview(ctx, tx, i, repo, input, budget)
		if e != nil {
			return nil, 0, e
		}
		if out.Current.State == out.Desired {
			return out, 200, nil
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.repository_lifecycle(tenant,repository,state,revision,reason,actor,change_sequence)VALUES($1,$2,$3,$4,$5,$6,$7)ON CONFLICT(tenant,repository)DO UPDATE SET state=excluded.state,revision=excluded.revision,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, repo, out.Desired, out.Current.Revision+1, input.Reason, i.Actor, sequence); e != nil {
			return nil, 0, e
		}
		if out.Desired != "active" {
			if _, e = tx.Exec(ctx, `UPDATE cratectl.retrievals SET generation=generation+1,state='failed',lease_until='epoch',fresh_until='epoch',stale_until='epoch',last_error='repository_inactive',changed_at=clock_timestamp(),change_sequence=$3 WHERE repository=$1 AND path=ANY($2::text[])`, repo, retrievals, sequence); e != nil {
				return nil, 0, e
			}
			if _, e = tx.Exec(ctx, `UPDATE cratectl.uploads SET state='cancelled',generation=generation+1,operation_token='',operation_until='epoch' WHERE repository=$1 AND id=ANY($2::text[])`, repo, uploads); e != nil {
				return nil, 0, e
			}
		}
		out.Current, e = repositoryStateInTx(ctx, tx, repo)
		return out, 200, e
	})
}

func jsonResult(value any, status int, e error) (Result, error) {
	if e != nil {
		return Result{}, e
	}
	data, e := json.Marshal(value)
	return Result{Body: data, Status: status}, e
}

// Canonical lifecycle paths cannot be mutable OCI tag aliases or catalogs.
func lifecycleOCIPath(p string) bool {
	for _, separator := range []string{"/manifests/sha256:", "/blobs/sha256:"} {
		if n := strings.LastIndex(p, separator); n > 0 && uploadDigest.MatchString(p[n+len(separator):]) {
			return true
		}
	}
	return false
}
