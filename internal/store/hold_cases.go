// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// A case identifies one independent preservation decision for one immutable
// reference. Releasing it never updates any other case or the legacy hold slot.
type HoldCase struct {
	Repository      string     `json:"repository"`
	Path            string     `json:"path"`
	Digest          string     `json:"digest"`
	CaseID          string     `json:"case_id"`
	Revision        int64      `json:"revision"`
	Held            bool       `json:"held"`
	Released        bool       `json:"released"`
	HoldReason      string     `json:"hold_reason,omitempty"`
	HoldUntil       *time.Time `json:"hold_until,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	Actor           string     `json:"actor,omitempty"`
	ChangedAt       *time.Time `json:"changed_at,omitempty"`
	CreatedSequence int64      `json:"created_sequence"`
	ChangeSequence  int64      `json:"change_sequence"`
}
type HoldCaseRequest struct {
	Path             string     `json:"path"`
	Digest           string     `json:"digest"`
	Action           string     `json:"action"`
	ExpectedRevision int64      `json:"expected_revision"`
	Reason           string     `json:"reason"`
	HoldUntil        *time.Time `json:"hold_until,omitempty"`
	DryRun           bool       `json:"dry_run"`
}
type HoldCasePreview struct {
	Case          HoldCase      `json:"case"`
	Current       ArtifactState `json:"current"`
	Action        string        `json:"action"`
	RetainedBytes bool          `json:"retained_bytes"`
	DryRun        bool          `json:"dry_run"`
}

func validCaseID(id string) bool { return Name.MatchString(id) && id != "legacy" }

const holdCaseColumns = `c.repository,c.path,c.digest,c.case_id,c.revision,
 NOT c.released AND (c.hold_until IS NULL OR c.hold_until>clock_timestamp()),
 c.released,c.hold_reason,c.hold_until,c.reason,c.actor,c.changed_at,c.created_sequence,c.change_sequence`

func scanHoldCase(row pgx.Row, c *HoldCase) error {
	return row.Scan(&c.Repository, &c.Path, &c.Digest, &c.CaseID, &c.Revision, &c.Held, &c.Released, &c.HoldReason, &c.HoldUntil, &c.Reason, &c.Actor, &c.ChangedAt, &c.CreatedSequence, &c.ChangeSequence)
}
func authorizeHoldCase(ctx context.Context, tx pgx.Tx, i Identity, repo, path, id string) (Artifact, error) {
	if i.Role != "admin" {
		return Artifact{}, ErrDenied
	}
	if !Name.MatchString(repo) || !validHoldPath(path) || !validCaseID(id) {
		return Artifact{}, ErrConflict
	}
	return holdReferenceInTx(ctx, tx, i, repo, path)
}
func holdCaseInTx(ctx context.Context, tx pgx.Tx, repo, path, id string) (HoldCase, error) {
	c := HoldCase{Repository: repo, Path: path, CaseID: id}
	e := scanHoldCase(tx.QueryRow(ctx, `SELECT `+holdCaseColumns+` FROM cratectl.artifact_hold_cases c WHERE repository=$1 AND path=$2 AND case_id=$3`, repo, path, id), &c)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, nil
	}
	return c, e
}
func (s *Store) HoldCase(ctx context.Context, i Identity, repo, path, id string) (HoldCase, error) {
	var c HoldCase
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		a, e := authorizeHoldCase(ctx, tx, i, repo, path, id)
		if e != nil {
			return e
		}
		c, e = holdCaseInTx(ctx, tx, repo, path, id)
		if c.Revision == 0 {
			c.Digest = a.Digest
		}
		return e
	})
	return c, e
}
func holdCasePreview(ctx context.Context, tx pgx.Tx, i Identity, repo, id string, input HoldCaseRequest) (HoldCasePreview, error) {
	out := HoldCasePreview{Action: input.Action, RetainedBytes: true, DryRun: input.DryRun}
	a, e := authorizeHoldCase(ctx, tx, i, repo, input.Path, id)
	if e != nil {
		return out, e
	}
	if input.ExpectedRevision < 0 || !utf8.ValidString(input.Reason) || !validLifecycleReason(input.Reason) || strings.TrimSpace(input.Reason) == "" {
		return out, ErrConflict
	}
	if a.Digest != input.Digest {
		return out, ErrLifecycleRevision
	}
	out.Case, e = holdCaseInTx(ctx, tx, repo, input.Path, id)
	if e != nil {
		return out, e
	}
	if out.Case.Revision != input.ExpectedRevision || out.Case.Revision > 0 && out.Case.Digest != a.Digest {
		return out, ErrLifecycleRevision
	}
	if out.Case.Revision == 0 {
		out.Case.Digest = a.Digest
	}
	out.Current, e = artifactStateInTx(ctx, tx, repo, input.Path)
	if e != nil {
		return out, e
	}
	if out.Current.Digest != "" && out.Current.Digest != a.Digest {
		return out, ErrLifecycleRevision
	}
	out.Current.Digest = a.Digest
	switch input.Action {
	case "hold":
		if input.HoldUntil != nil {
			var future bool
			if e = tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp()`, input.HoldUntil).Scan(&future); e != nil {
				return out, e
			}
			if !future {
				return out, ErrConflict
			}
		}
	case "release_hold":
		if input.HoldUntil != nil || out.Case.Revision == 0 || out.Case.Released {
			return out, ErrConflict
		}
	default:
		return out, ErrConflict
	}
	return out, nil
}
func (s *Store) ChangeHoldCase(ctx context.Context, i Identity, repo, id, key, fp string, input HoldCaseRequest) (Result, error) {
	if input.DryRun {
		var out HoldCasePreview
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; out, e = holdCasePreview(ctx, tx, i, repo, id, input); return e })
		return jsonResult(out, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "artifact.hold_case.changed", true, func(tx pgx.Tx) error { _, e := authorizeHoldCase(ctx, tx, i, repo, input.Path, id); return e }, func(tx pgx.Tx) (any, int, error) {
		out, e := holdCasePreview(ctx, tx, i, repo, id, input)
		if e != nil {
			return nil, 0, e
		}
		seq, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		c := out.Case
		if input.Action == "hold" {
			c.HoldReason = input.Reason
			c.HoldUntil = input.HoldUntil
		}
		if c.CreatedSequence == 0 {
			c.CreatedSequence = seq
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifact_hold_cases(tenant,repository,path,case_id,digest,revision,released,hold_reason,hold_until,reason,actor,created_sequence,change_sequence)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
 ON CONFLICT(tenant,repository,path,case_id) DO UPDATE SET revision=excluded.revision,released=excluded.released,hold_reason=excluded.hold_reason,hold_until=excluded.hold_until,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, repo, input.Path, id, input.Digest, c.Revision+1, input.Action == "release_hold", c.HoldReason, c.HoldUntil, input.Reason, i.Actor, c.CreatedSequence, seq)
		if e != nil {
			return nil, 0, e
		}
		// Also fence already-previewed deletion/restoration/retention. Preserve the
		// legacy slot and tombstone while each case advances its own revision.
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,revision,reason,actor,change_sequence)
 VALUES($1,$2,$3,$4,1,$5,$6,$7) ON CONFLICT(tenant,repository,path) DO UPDATE SET revision=artifact_lifecycle.revision+1,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, repo, input.Path, input.Digest, input.Reason, i.Actor, seq)
		if e != nil {
			return nil, 0, e
		}
		out.Case, e = holdCaseInTx(ctx, tx, repo, input.Path, id)
		if e != nil {
			return nil, 0, e
		}
		out.Current, e = artifactStateInTx(ctx, tx, repo, input.Path)
		return out, 200, e
	})
}
