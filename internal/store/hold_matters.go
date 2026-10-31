// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

var ErrMatterInput = errors.New("invalid hold matter request")
var ErrMatterChanged = errors.New("hold matter or reviewed membership changed")
var ErrMatterBudget = errors.New("complete hold matter manifest exceeds resource budget")
var ErrMatterAuthorization = errors.New("hold matter requester or approver authority changed")

type HoldMatter struct {
	Name            string    `json:"name"`
	Revision        int64     `json:"revision"`
	State           string    `json:"state"`
	Title           string    `json:"title"`
	Reason          string    `json:"reason"`
	Actor           string    `json:"actor"`
	CreatedSequence int64     `json:"created_sequence"`
	ChangeSequence  int64     `json:"change_sequence"`
	ChangedAt       time.Time `json:"changed_at"`
}
type HoldMatterRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	State            string `json:"state"`
	Title            string `json:"title"`
	Reason           string `json:"reason"`
	DryRun           bool   `json:"dry_run"`
}

func matterReason(s string) bool {
	return utf8.ValidString(s) && validLifecycleReason(s) && strings.TrimSpace(s) != ""
}

const matterColumns = `name,revision,state,title,reason,actor,created_sequence,change_sequence,changed_at`

func scanMatter(row pgx.Row, m *HoldMatter) error {
	return row.Scan(&m.Name, &m.Revision, &m.State, &m.Title, &m.Reason, &m.Actor, &m.CreatedSequence, &m.ChangeSequence, &m.ChangedAt)
}
func matterInTx(ctx context.Context, tx pgx.Tx, name string) (HoldMatter, error) {
	m := HoldMatter{Name: name}
	e := scanMatter(tx.QueryRow(ctx, `SELECT `+matterColumns+` FROM cratectl.hold_matters WHERE name=$1`, name), &m)
	if errors.Is(e, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, e
}
func matterAdmin(i Identity, name string) error {
	if i.Role != "admin" {
		return ErrDenied
	}
	if !Name.MatchString(name) {
		return ErrMatterInput
	}
	return nil
}
func (s *Store) HoldMatter(ctx context.Context, i Identity, name string) (HoldMatter, error) {
	var m HoldMatter
	if e := matterAdmin(i, name); e != nil {
		return m, e
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; m, e = matterInTx(ctx, tx, name); return e })
	return m, e
}
func prepareMatter(ctx context.Context, tx pgx.Tx, i Identity, name string, r HoldMatterRequest) (HoldMatter, error) {
	m := HoldMatter{Name: name}
	if e := matterAdmin(i, name); e != nil {
		return m, e
	}
	if r.ExpectedRevision < 0 || r.ExpectedRevision == math.MaxInt64 || !matterReason(r.Title) || len(r.Title) > 256 || !matterReason(r.Reason) || (r.State != "open" && r.State != "closed") {
		return m, ErrMatterInput
	}
	old, e := matterInTx(ctx, tx, name)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return m, e
	}
	if old.Revision != r.ExpectedRevision {
		return m, ErrMatterChanged
	}
	if r.State == "closed" {
		if old.Revision == 0 {
			return m, ErrMatterInput
		}
		var busy bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.hold_matter_members WHERE matter=$1 AND NOT released) OR EXISTS(SELECT 1 FROM cratectl.hold_matter_operations o LEFT JOIN cratectl.jobs j ON (j.tenant,j.sequence,j.task)=(o.tenant,o.job_sequence,o.job_task) WHERE o.matter=$1 AND (o.state='awaiting_approval' OR o.state='approved' AND j.state NOT IN ('succeeded','failed','cancelled')))`, name).Scan(&busy)
		if e != nil {
			return m, e
		}
		if busy {
			return m, ErrMatterChanged
		}
	}
	m = HoldMatter{Name: name, Revision: old.Revision + 1, State: r.State, Title: r.Title, Reason: r.Reason, Actor: i.Actor, CreatedSequence: old.CreatedSequence}
	return m, nil
}
func (s *Store) SetHoldMatter(ctx context.Context, i Identity, name, key, fp string, r HoldMatterRequest) (Result, error) {
	if e := matterAdmin(i, name); e != nil {
		return Result{}, e
	}
	if r.DryRun {
		var m HoldMatter
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; m, e = prepareMatter(ctx, tx, i, name, r); return e })
		return jsonResult(map[string]any{"matter_name": name, "matter": m, "dry_run": true, "retained_bytes": true}, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "hold.matter.changed", true, func(tx pgx.Tx) error { return matterAdmin(i, name) }, func(tx pgx.Tx) (any, int, error) {
		m, e := prepareMatter(ctx, tx, i, name, r)
		if e != nil {
			return nil, 0, e
		}
		seq, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		if m.CreatedSequence == 0 {
			m.CreatedSequence = seq
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.hold_matters(tenant,name,revision,state,title,reason,actor,created_sequence,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant,name) DO UPDATE SET revision=excluded.revision,state=excluded.state,title=excluded.title,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, name, m.Revision, m.State, m.Title, m.Reason, i.Actor, m.CreatedSequence, seq)
		if e != nil {
			return nil, 0, e
		}
		m, e = matterInTx(ctx, tx, name)
		return map[string]any{"matter_name": name, "matter": m, "dry_run": false, "retained_bytes": true}, 200, e
	})
}

// A preservation decision needs only a bounded immutable coordinate. Package
// metadata is neither fetched nor interpreted while authorizing a hold.
func holdReferenceInTx(ctx context.Context, tx pgx.Tx, i Identity, repo, path string) (Artifact, error) {
	if i.Role != "admin" {
		return Artifact{}, ErrDenied
	}
	if !Name.MatchString(repo) || !validHoldPath(path) {
		return Artifact{}, ErrMatterInput
	}
	r, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return Artifact{}, e
	}
	if r.Format != "oci" || r.Mode == "group" {
		return Artifact{}, ErrConflict
	}
	a := Artifact{Repository: repo, Path: path}
	e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, path).Scan(&a.Digest)
	if errors.Is(e, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if e == nil && !strings.HasSuffix(path, "sha256:"+a.Digest) {
		return a, ErrConflict
	}
	return a, e
}

type HoldMatterMember struct {
	Matter          string     `json:"matter"`
	Repository      string     `json:"repository"`
	Path            string     `json:"path"`
	Digest          string     `json:"digest"`
	Revision        int64      `json:"revision"`
	Held            bool       `json:"held"`
	Released        bool       `json:"released"`
	HoldReason      string     `json:"hold_reason,omitempty"`
	HoldUntil       *time.Time `json:"hold_until,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	Actor           string     `json:"actor,omitempty"`
	CreatedSequence int64      `json:"created_sequence"`
	ChangeSequence  int64      `json:"change_sequence"`
	ChangedAt       *time.Time `json:"changed_at,omitempty"`
}

const matterMemberColumns = `m.matter,m.repository,m.path,m.digest,m.revision,NOT m.released AND (m.hold_until IS NULL OR m.hold_until>clock_timestamp()),m.released,m.hold_reason,m.hold_until,m.reason,m.actor,m.created_sequence,m.change_sequence,m.changed_at`

func scanMatterMember(row pgx.Row, m *HoldMatterMember) error {
	return row.Scan(&m.Matter, &m.Repository, &m.Path, &m.Digest, &m.Revision, &m.Held, &m.Released, &m.HoldReason, &m.HoldUntil, &m.Reason, &m.Actor, &m.CreatedSequence, &m.ChangeSequence, &m.ChangedAt)
}
func matterMemberInTx(ctx context.Context, tx pgx.Tx, matter, repo, path string) (HoldMatterMember, error) {
	m := HoldMatterMember{Matter: matter, Repository: repo, Path: path}
	e := scanMatterMember(tx.QueryRow(ctx, `SELECT `+matterMemberColumns+` FROM cratectl.hold_matter_members m WHERE matter=$1 AND repository=$2 AND path=$3`, matter, repo, path), &m)
	if errors.Is(e, pgx.ErrNoRows) {
		return m, nil
	}
	return m, e
}
