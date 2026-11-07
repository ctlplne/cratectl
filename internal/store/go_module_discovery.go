// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

// A current source list is discovery, not package approval. Reuse the common
// artifact policy/lifecycle/cache path, deliberately without package review.
// GoModuleView separately applies review to each complete package bundle.
func goModuleCatalogInTx(ctx context.Context, tx pgx.Tx, source Repository, mod string, budget *int64, admissions []NativeAdmission) (GoModuleCatalog, error) {
	_, catalog, e := readGoModuleCatalogInTx(ctx, tx, source, mod, budget, admissions)
	return catalog, e
}

// GoModuleCatalogArtifact reads a typed advertisement through the same bounded
// current-source/policy/cache path used by complete discovery. The raw list is
// not package approval and cannot be served by the package-byte adapter.
func (s *Store) GoModuleCatalogArtifact(ctx context.Context, i Identity, repo, mod string, revision, budget int64, admissions ...NativeAdmission) (Artifact, error) {
	p := GoModuleCatalogPath(mod)
	request, e := gomodule.ParseRequest(strings.TrimPrefix(p, "go-catalog/") + "/@v/list")
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
		if e := goChecksumRepositoryUsable(ctx, tx, r); e != nil {
			return e
		}
		a, _, e = readGoModuleCatalogInTx(ctx, tx, r, mod, &budget, admissions)
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

func readGoModuleCatalogInTx(ctx context.Context, tx pgx.Tx, source Repository, mod string, budget *int64, admissions []NativeAdmission) (Artifact, GoModuleCatalog, error) {
	p := GoModuleCatalogPath(mod)
	var state Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, source.Name, p), &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return Artifact{}, GoModuleCatalog{}, ErrGoModuleCacheExpired
	}
	if e != nil {
		return Artifact{}, GoModuleCatalog{}, e
	}
	if state.SourceRevision != source.SourceRevision {
		return Artifact{}, GoModuleCatalog{}, ErrSourceChanged
	}
	if goModuleNegativeAdmitted(state, admissions) {
		return Artifact{}, GoModuleCatalog{Module: mod, Versions: []string{}}, nil
	}
	if state.State == "negative" {
		if state.LastStatus != 404 {
			return Artifact{}, GoModuleCatalog{}, ErrGoModuleUnvalidated
		}
		return Artifact{}, GoModuleCatalog{}, ErrGoModuleCacheExpired
	}
	if *budget < 1 {
		return Artifact{}, GoModuleCatalog{}, ErrMetadataLimit
	}
	b := repositoryReadBudget(source)
	b.metadataBytes = *budget
	b.sqlMetadataBytes = min(*budget, MaxGoModuleCatalog)
	b.cacheRepository, b.admissions = source.Name, admissions
	a, e := readArtifact(ctx, tx, source.Name, p, false, b)
	if errors.Is(e, ErrNotFound) {
		return Artifact{}, GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	if errors.Is(e, ErrOCICacheExpired) || errors.Is(e, ErrOCICache) {
		return Artifact{}, GoModuleCatalog{}, ErrGoModuleCacheExpired
	}
	if e != nil {
		return Artifact{}, GoModuleCatalog{}, e
	}
	if len(a.Metadata) == 0 {
		return Artifact{}, GoModuleCatalog{}, ErrMetadataLimit
	}
	*budget -= int64(len(a.Path) + len(a.Metadata) + len(a.MediaType) + 192)
	if *budget < 0 {
		return Artifact{}, GoModuleCatalog{}, ErrMetadataLimit
	}
	c, e := ValidateGoModuleCatalogArtifact(a)
	if e != nil || c.Module != mod {
		return Artifact{}, GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	return a, c, nil
}

func addGoModuleAdvertisements(candidates map[string]bool, catalog GoModuleCatalog, review bool) {
	for _, version := range catalog.Versions {
		if _, known := candidates[version]; !known {
			// Missing scan evidence stays unassessed. A catalog never approves
			// an unknown version or overrides a cached denial/tombstone.
			candidates[version] = !review
		}
	}
}
