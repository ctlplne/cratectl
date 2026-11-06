// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

// Current latest hints are metadata, not package bytes. Read their canonical
// binding, source, grants, policy and cache admission in one bounded snapshot.
func (s *Store) GoModuleLatestArtifact(ctx context.Context, i Identity, repo, mod string, revision, budget int64, admissions ...NativeAdmission) (Artifact, error) {
	p := GoModuleLatestPath(mod)
	request, e := gomodule.ParseRequest(strings.TrimPrefix(p, "go-latest/") + "/@latest")
	if p == "" || e != nil || request.Module != mod || revision < 0 || budget < 1 || budget > 64<<20 || len(admissions) > 1 {
		return Artifact{}, ErrGoModuleUnvalidated
	}
	var a Artifact
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
		a, _, e = readGoModuleLatestInTx(ctx, tx, r, mod, &budget, admissions)
		if e == nil && a.Path == "" {
			return ErrNotFound
		}
		return e
	})
	if e != nil {
		return Artifact{}, e
	}
	return a, nil
}

func readGoModuleLatestInTx(ctx context.Context, tx pgx.Tx, r Repository, mod string, budget *int64, admissions []NativeAdmission) (Artifact, GoModuleLatest, error) {
	p := GoModuleLatestPath(mod)
	var state Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, r.Name, p), &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return Artifact{}, GoModuleLatest{}, ErrGoModuleCacheExpired
	}
	if e != nil {
		return Artifact{}, GoModuleLatest{}, e
	}
	if state.SourceRevision != r.SourceRevision {
		return Artifact{}, GoModuleLatest{}, ErrSourceChanged
	}
	if goModuleNegativeAdmitted(state, admissions) {
		return Artifact{}, GoModuleLatest{}, nil
	}
	if state.State == "negative" {
		if state.LastStatus != 404 {
			return Artifact{}, GoModuleLatest{}, ErrGoModuleUnvalidated
		}
		return Artifact{}, GoModuleLatest{}, ErrGoModuleCacheExpired
	}
	if *budget < 1 {
		return Artifact{}, GoModuleLatest{}, ErrMetadataLimit
	}
	b := repositoryReadBudget(r)
	b.metadataBytes = *budget
	b.sqlMetadataBytes = min(*budget, MaxGoModuleLatestMetadata)
	b.cacheRepository = r.Name
	b.admissions = admissions
	a, e := readArtifact(ctx, tx, r.Name, p, false, b)
	if errors.Is(e, ErrNotFound) {
		return Artifact{}, GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	if errors.Is(e, ErrOCICacheExpired) || errors.Is(e, ErrOCICache) {
		return Artifact{}, GoModuleLatest{}, ErrGoModuleCacheExpired
	}
	if e != nil {
		return Artifact{}, GoModuleLatest{}, e
	}
	if len(a.Metadata) == 0 {
		return Artifact{}, GoModuleLatest{}, ErrMetadataLimit
	}
	*budget -= int64(len(a.Path) + len(a.MediaType) + len(a.Metadata) + 192)
	if *budget < 0 {
		return Artifact{}, GoModuleLatest{}, ErrMetadataLimit
	}
	hint, e := ValidateGoModuleLatestArtifact(a)
	if e != nil || hint.Module != mod {
		return Artifact{}, GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	return a, hint, nil
}
