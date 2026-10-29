// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type ArtifactStateRequest struct {
	Path             string     `json:"path"`
	Digest           string     `json:"digest"`
	Action           string     `json:"action"`
	ExpectedRevision int64      `json:"expected_revision"`
	Reason           string     `json:"reason"`
	HoldUntil        *time.Time `json:"hold_until,omitempty"`
	DryRun           bool       `json:"dry_run"`
}
type ArtifactStatePreview struct {
	Current          ArtifactState `json:"current"`
	Action           string        `json:"action"`
	StrongParents    []string      `json:"strong_parents"`
	Tags             []string      `json:"tags"`
	WeakSubjects     []string      `json:"weak_subject_dependents"`
	ActiveRetrievals int           `json:"active_retrievals"`
	RetainedBytes    bool          `json:"retained_bytes"`
	DryRun           bool          `json:"dry_run"`
}

func artifactLifecycleRecord(ctx context.Context, tx pgx.Tx, i Identity, repo, path string) (Artifact, error) {
	r, e := repositoryInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return Artifact{}, e
	}
	if r.Format != "oci" || r.Mode == "group" || !lifecycleOCIPath(path) {
		return Artifact{}, ErrConflict
	}
	var a Artifact
	e = scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, path), &a)
	if errors.Is(e, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if e == nil && !strings.HasSuffix(path, "sha256:"+a.Digest) {
		return a, ErrConflict
	}
	return a, e
}

func artifactStatePreview(ctx context.Context, tx pgx.Tx, i Identity, repo string, input ArtifactStateRequest, budget int) (ArtifactStatePreview, error) {
	out := ArtifactStatePreview{Action: input.Action, StrongParents: []string{}, Tags: []string{}, WeakSubjects: []string{}, RetainedBytes: true, DryRun: input.DryRun}
	if !i.CanWrite() {
		return out, ErrDenied
	}
	if budget < 1 || budget > 1000000 || input.ExpectedRevision < 0 || !validLifecycleReason(input.Reason) {
		return out, ErrConflict
	}
	a, e := artifactLifecycleRecord(ctx, tx, i, repo, input.Path)
	if e != nil {
		return out, e
	}
	if input.Action == "delete" && strings.HasSuffix(input.Path, "/manifests/sha256:"+a.Digest) {
		var metadata OCIManifestMetadata
		if json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated {
			return out, ErrOCIUnvalidated
		}
	}
	out.Current, e = artifactStateInTx(ctx, tx, repo, input.Path)
	if e != nil {
		return out, e
	}
	if a.Digest != input.Digest || out.Current.Revision != input.ExpectedRevision || out.Current.Digest != "" && out.Current.Digest != a.Digest {
		return out, ErrLifecycleRevision
	}
	out.Current.Digest = a.Digest
	switch input.Action {
	case "delete", "restore":
	case "hold", "release_hold":
		if i.Role != "admin" {
			return out, ErrDenied
		}
		if input.Action == "hold" && strings.TrimSpace(input.Reason) == "" {
			return out, ErrConflict
		}
	default:
		return out, ErrConflict
	}
	if input.HoldUntil != nil {
		var future bool
		if input.Action != "hold" {
			return out, ErrConflict
		}
		if e = tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp()`, input.HoldUntil).Scan(&future); e != nil {
			return out, e
		}
		if !future {
			return out, ErrConflict
		}
	}
	remainingBytes := 8 << 20
	query := func(sql string, args ...any) ([]string, error) {
		rows, e := tx.Query(ctx, sql, args...)
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
	out.StrongParents, e = query(`SELECT a.path FROM cratectl.artifacts a WHERE a.repository=$1 AND (a.metadata->'oci_references') ? $2 AND NOT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle l WHERE (l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path) AND l.deleted) ORDER BY a.path LIMIT $3`, repo, input.Path, budget+1)
	if e != nil {
		return out, e
	}
	if n := strings.LastIndex(input.Path, "/manifests/"); n > 0 {
		image := input.Path[:n]
		out.Tags, e = query(`SELECT tag FROM cratectl.tags WHERE repository=$1 AND image=$2 AND digest=$3 AND NOT deleted ORDER BY tag LIMIT $4`, repo, image, "sha256:"+a.Digest, budget+1)
		if e != nil {
			return out, e
		}
		out.WeakSubjects, e = query(`SELECT a.path FROM cratectl.artifacts a WHERE a.repository=$1 AND starts_with(a.path,$2) AND a.metadata->'oci_subject'->>'digest'=$3 AND NOT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle l WHERE (l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path) AND l.deleted) ORDER BY a.path LIMIT $4`, repo, image+"/manifests/", "sha256:"+a.Digest, budget+1)
		if e != nil {
			return out, e
		}
	}
	paths, e := query(`SELECT path FROM cratectl.retrievals WHERE repository=$1 AND path=$2 AND state='fetching' AND lease_until>clock_timestamp() ORDER BY path LIMIT $3`, repo, input.Path, budget+1)
	out.ActiveRetrievals = len(paths)
	return out, e
}

func (s *Store) ArtifactState(ctx context.Context, i Identity, repo, path string) (ArtifactState, error) {
	var state ArtifactState
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		a, e := artifactLifecycleRecord(ctx, tx, i, repo, path)
		if e != nil {
			return e
		}
		state, e = artifactStateInTx(ctx, tx, repo, path)
		state.Digest = a.Digest
		return e
	})
	return state, e
}

// RestorationGraph is administrative intake metadata, never serving authority.
// Only the requested root may be deleted. Existing policy decisions are retained.
func restorationGraph(ctx context.Context, tx pgx.Tx, repo, path string) ([]Artifact, error) {
	b := newGraphBudget()
	b.retained = true
	b.retainedRoot = path
	if _, e := readArtifact(ctx, tx, repo, path, false, b); e != nil {
		return nil, e
	}
	out := make([]Artifact, 0, len(b.checked))
	for _, a := range b.checked {
		out = append(out, Artifact{Repository: a.Repository, Path: a.Path, Digest: a.Digest, Size: a.Size, MediaType: a.MediaType, Metadata: a.Metadata})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
func (s *Store) RestorationGraph(ctx context.Context, i Identity, repo string, input ArtifactStateRequest) ([]Artifact, error) {
	var out []Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if !i.CanWrite() {
			return ErrDenied
		}
		if input.Action != "restore" {
			return ErrConflict
		}
		preview, e := artifactStatePreview(ctx, tx, i, repo, input, 4096)
		if e != nil {
			return e
		}
		if preview.Current.Held {
			return ErrHeld
		}
		out, e = restorationGraph(ctx, tx, repo, input.Path)
		return e
	})
	return out, e
}

// verified is produced by the service after verifying every retained CAS object
// outside SQL. The current graph is compared again under the tenant write lock.
func (s *Store) ChangeArtifactState(ctx context.Context, i Identity, repo, key, fp string, input ArtifactStateRequest, budget int, verified []Artifact) (Result, error) {
	if input.DryRun {
		var out ArtifactStatePreview
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			var e error
			out, e = artifactStatePreview(ctx, tx, i, repo, input, budget)
			return e
		})
		return jsonResult(out, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "artifact.lifecycle.changed", true, func(tx pgx.Tx) error { return authorizeArtifactLifecycle(ctx, tx, i, repo, input) }, func(tx pgx.Tx) (any, int, error) {
		return changeArtifactState(ctx, tx, i, repo, input, budget, verified)
	})
}

func authorizeArtifactLifecycle(ctx context.Context, tx pgx.Tx, i Identity, repo string, input ArtifactStateRequest) error {
	if !i.CanWrite() || (input.Action == "hold" || input.Action == "release_hold") && i.Role != "admin" {
		return ErrDenied
	}
	_, e := artifactLifecycleRecord(ctx, tx, i, repo, input.Path)
	return e
}
func (s *Store) ReplayArtifactLifecycle(ctx context.Context, i Identity, repo, key, fp string, input ArtifactStateRequest) (Result, bool, error) {
	return s.replayMutationChecked(ctx, i, key, fp, func(tx pgx.Tx) error { return authorizeArtifactLifecycle(ctx, tx, i, repo, input) })
}
func changeArtifactState(ctx context.Context, tx pgx.Tx, i Identity, repo string, input ArtifactStateRequest, budget int, verified []Artifact) (any, int, error) {
	out, e := artifactStatePreview(ctx, tx, i, repo, input, budget)
	if e != nil {
		return nil, 0, e
	}
	state := out.Current
	if state.Held && (input.Action == "delete" || input.Action == "restore") {
		return nil, 0, ErrHeld
	}
	switch input.Action {
	case "delete":
		if len(out.StrongParents) > 0 {
			return nil, 0, ErrReferenced
		}
		state.Deleted = true
	case "restore":
		if !state.Deleted {
			return nil, 0, ErrConflict
		}
		current, e := restorationGraph(ctx, tx, repo, input.Path)
		if e != nil {
			return nil, 0, e
		}
		left, _ := json.Marshal(current)
		right, _ := json.Marshal(verified)
		if len(verified) == 0 || !bytes.Equal(left, right) {
			return nil, 0, ErrLifecycleRevision
		}
		state.Deleted = false
	case "hold":
		state.HoldReason = input.Reason
		state.HoldUntil = input.HoldUntil
	case "release_hold":
		state.HoldReason = ""
		state.HoldUntil = nil
	}
	sequence, e := nextEventSequence(ctx, tx, i)
	if e != nil {
		return nil, 0, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,deleted,revision,hold_reason,hold_until,reason,actor,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant,repository,path) DO UPDATE SET deleted=excluded.deleted,revision=excluded.revision,hold_reason=excluded.hold_reason,hold_until=excluded.hold_until,reason=excluded.reason,actor=excluded.actor,change_sequence=excluded.change_sequence,changed_at=clock_timestamp()`, i.Tenant, repo, input.Path, input.Digest, state.Deleted, state.Revision+1, state.HoldReason, state.HoldUntil, input.Reason, i.Actor, sequence)
	if e != nil {
		return nil, 0, e
	}
	if input.Action == "delete" {
		_, e = tx.Exec(ctx, `UPDATE cratectl.retrievals SET generation=generation+1,state='failed',lease_until='epoch',fresh_until='epoch',stale_until='epoch',last_error='artifact_deleted',changed_at=clock_timestamp(),change_sequence=$3 WHERE repository=$1 AND path=$2 AND state='fetching'`, repo, input.Path, sequence)
		if e != nil {
			return nil, 0, e
		}
	}
	out.Current, e = artifactStateInTx(ctx, tx, repo, input.Path)
	return out, 200, e
}

// Native OCI deletion resolves the current revision atomically. Tags retain a
// separate deleted binding, so restoring a manifest cannot resurrect a tag that
// was explicitly deleted or overwrite a newer tag target.
func (s *Store) DeleteOCI(ctx context.Context, i Identity, repo, image, kind, ref string, budget int) (Result, error) {
	return s.MutateRepository(ctx, i, repo, "", "", "oci.reference.deleted", func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Format != "oci" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		if kind != "manifests" && kind != "blobs" {
			return nil, 0, ErrConflict
		}
		if !strings.HasPrefix(ref, "sha256:") {
			if kind != "manifests" {
				return nil, 0, ErrConflict
			}
			var digest string
			if e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3 AND NOT deleted`, repo, image, ref).Scan(&digest); errors.Is(e, pgx.ErrNoRows) {
				return nil, 0, ErrNotFound
			} else if e != nil {
				return nil, 0, e
			}
			state, e := artifactStateInTx(ctx, tx, repo, image+"/manifests/"+digest)
			if e != nil {
				return nil, 0, e
			}
			if state.Held {
				return nil, 0, ErrHeld
			}
			sequence, e := nextEventSequence(ctx, tx, i)
			if e != nil {
				return nil, 0, e
			}
			_, e = tx.Exec(ctx, `UPDATE cratectl.tags SET deleted=true,version=version+1,changed_at=clock_timestamp(),change_sequence=$4 WHERE repository=$1 AND image=$2 AND tag=$3`, repo, image, ref, sequence)
			return map[string]string{"repository": repo, "image": image, "tag": ref, "digest": digest}, 202, e
		}
		path := image + "/" + kind + "/" + ref
		state, e := artifactStateInTx(ctx, tx, repo, path)
		if e != nil {
			return nil, 0, e
		}
		out, _, e := changeArtifactState(ctx, tx, i, repo, ArtifactStateRequest{Path: path, Digest: strings.TrimPrefix(ref, "sha256:"), ExpectedRevision: state.Revision, Action: "delete", Reason: "native OCI DELETE"}, budget, nil)
		return out, 202, e
	})
}
