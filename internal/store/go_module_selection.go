// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/module"
)

func goModuleNegativeAdmitted(state Retrieval, admissions []NativeAdmission) bool {
	if state.SourceChanged || state.Generation < 1 || state.State != "negative" || state.LastStatus != 404 {
		return false
	}
	if state.Fresh() {
		return true
	}
	// A no-cache 404 can admit this one request's fallback, without making
	// later requests fresh. The same root generation must still be current.
	for _, a := range admissions {
		if !a.Stale && a.Repository == state.Repository && a.Path == state.Path && a.Generation == state.Generation {
			return true
		}
	}
	return false
}

// A catalog omission cannot establish absence of an exact version or pseudo
// version. A group may skip a proxy only after a fresh negative version intake
// with no prior publication witness; all other states require current intake.
func goModuleProxyAbsentInTx(ctx context.Context, tx pgx.Tx, r Repository, c gomodule.Coordinate, admissions []NativeAdmission) (bool, error) {
	if err := goChecksumRepositoryUsable(ctx, tx, r); err != nil {
		return false, err
	}
	p := c.Prefix() + ".zip"
	var state Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, r.Name, p), &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, ErrGoModuleCacheExpired
	}
	if e != nil {
		return false, e
	}
	if state.SourceRevision != r.SourceRevision {
		return false, ErrSourceChanged
	}
	if state.State == "fetching" {
		return false, ErrBusy
	}
	if state.State != "negative" {
		return false, nil
	}
	if state.LastStatus != 404 {
		return false, ErrGoModuleUnvalidated
	}
	if !goModuleNegativeAdmitted(state, admissions) {
		return false, nil
	}
	var known bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=ANY($2::text[]))`, r.Name, []string{c.Prefix() + ".zip", c.Prefix() + ".mod", c.Prefix() + ".info"}).Scan(&known)
	if e != nil {
		return false, e
	}
	if known {
		return false, ErrDenied
	}
	if state.ValidationRoot != "" || state.ValidationGeneration != 0 {
		return false, ErrGoModuleUnvalidated
	}
	return true, nil
}

func (s *Store) GoModuleProxyAbsent(ctx context.Context, i Identity, repo, p string, revision int64, admissions ...NativeAdmission) (bool, error) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Operation != "zip" || revision < 0 || len(admissions) > 1 {
		return false, ErrGoModuleUnvalidated
	}
	var absent bool
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "go" || r.Mode != "proxy" {
			return ErrConflict
		}
		if r.SourceRevision != revision {
			return ErrSourceChanged
		}
		absent, e = goModuleProxyAbsentInTx(ctx, tx, r, request.Coordinate, admissions)
		return e
	})
	if e != nil {
		return false, e
	}
	return absent, nil
}

// GoModuleSelectionAtRevision is the final serving guard, after disk readback.
// It reselects current precedence rather than checking only the old source, so
// a new higher-priority publication cannot be bypassed by an in-flight request.
// No network effects occur inside this read snapshot. Public proxy mode remains
// disabled until the bounded caller/lease/intake paths are fully integrated.
func (s *Store) GoModuleSelectionAtRevision(ctx context.Context, i Identity, endpoint, p string, snapshot SourceSnapshot, admissions ...NativeAdmission) (Artifact, Repository, error) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Version == "" || snapshot.Repository == "" || snapshot.Revision < 0 || len(snapshot.Groups) > 1 || len(admissions) > 64 {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	escaped, e := module.EscapePath(request.Module)
	if e != nil {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	var selected Artifact
	var source Repository
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		return goModuleSelectionInTx(ctx, tx, i, endpoint, p, escaped, request, snapshot, admissions, &selected, &source)
	})
	if e != nil {
		return Artifact{}, Repository{}, e
	}
	return selected, source, nil
}

func goModuleSelectionInTx(ctx context.Context, tx pgx.Tx, i Identity, endpoint, p, escaped string, request gomodule.Request, snapshot SourceSnapshot, admissions []NativeAdmission, selected *Artifact, source *Repository) error {
	group, e := repositoryInTx(ctx, tx, i, endpoint, "read")
	if e != nil {
		return e
	}
	if group.Format != "go" {
		return ErrConflict
	}
	if group.Mode == "group" {
		revision, present := snapshot.Groups[group.Name]
		if len(snapshot.Groups) != 1 || !present || revision != group.SourceRevision {
			return ErrSourceChanged
		}
	} else if len(snapshot.Groups) != 0 {
		return ErrSourceChanged
	}
	for _, name := range MembersForPath(group, escaped+"/") {
		r, e := repositoryInTx(ctx, tx, i, name, "read")
		if e != nil {
			return e
		}
		if r.Format != "go" {
			return ErrConflict
		}
		review := r.RequireReview || group.RequireReview
		var a Artifact
		switch r.Mode {
		case "hosted":
			b := repositoryReadBudget(r)
			a, e = readArtifact(ctx, tx, r.Name, p, review, b)
			if errors.Is(e, ErrNotFound) {
				e = missingGoModuleRepresentation(ctx, tx, r.Name, p)
			}
			if errors.Is(e, ErrNotFound) {
				continue
			}
			if e == nil {
				e = checkGoModuleBundle(ctx, tx, r.Name, a, review, b)
			}
		case "proxy":
			absent, err := goModuleProxyAbsentInTx(ctx, tx, r, request.Coordinate, admissions)
			if err != nil {
				return err
			}
			if absent {
				continue
			}
			ownAdmissions := []NativeAdmission{}
			for _, admission := range admissions {
				if admission.Repository == r.Name && admission.Path == request.Coordinate.Prefix()+".zip" {
					ownAdmissions = append(ownAdmissions, admission)
				}
			}
			if len(ownAdmissions) > 1 {
				return ErrGoModuleUnvalidated
			}
			a, e = goModuleProxyArtifactInTx(ctx, tx, r, p, request.Coordinate, review, ownAdmissions)
		default:
			return ErrConflict
		}
		if e != nil {
			return e
		}
		if r.Name != snapshot.Repository {
			return ErrConflict
		}
		if _, e = checkSourceSnapshot(ctx, tx, i, r, snapshot); e != nil {
			return e
		}
		*selected, *source = a, r
		return nil
	}
	// This API guards an already resolved object. Losing its selection is
	// not a new absence that can authorize a package client's fallback.
	return ErrConflict
}
