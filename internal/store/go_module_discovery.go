// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// A current source list is discovery, not package approval. Reuse the common
// artifact policy/lifecycle/cache path, deliberately without package review.
// GoModuleView separately applies review to each complete package bundle.
func goModuleCatalogInTx(ctx context.Context, tx pgx.Tx, source Repository, mod string, budget *int64, admissions []NativeAdmission) (GoModuleCatalog, error) {
	p := GoModuleCatalogPath(mod)
	var state Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, source.Name, p), &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return GoModuleCatalog{}, ErrGoModuleCacheExpired
	}
	if e != nil {
		return GoModuleCatalog{}, e
	}
	if state.SourceRevision != source.SourceRevision {
		return GoModuleCatalog{}, ErrSourceChanged
	}
	if state.State == "negative" && state.Fresh() {
		return GoModuleCatalog{Module: mod, Versions: []string{}}, nil
	}
	if *budget < 1 {
		return GoModuleCatalog{}, ErrMetadataLimit
	}
	b := repositoryReadBudget(source)
	b.metadataBytes = *budget
	b.sqlMetadataBytes = min(*budget, MaxGoModuleCatalog)
	b.cacheRepository, b.admissions = source.Name, admissions
	a, e := readArtifact(ctx, tx, source.Name, p, false, b)
	if errors.Is(e, ErrNotFound) {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	if errors.Is(e, ErrOCICacheExpired) || errors.Is(e, ErrOCICache) {
		return GoModuleCatalog{}, ErrGoModuleCacheExpired
	}
	if e != nil {
		return GoModuleCatalog{}, e
	}
	if len(a.Metadata) == 0 {
		return GoModuleCatalog{}, ErrMetadataLimit
	}
	*budget -= int64(len(a.Path) + len(a.Metadata) + len(a.MediaType) + 192)
	if *budget < 0 {
		return GoModuleCatalog{}, ErrMetadataLimit
	}
	c, e := ValidateGoModuleCatalogArtifact(a)
	if e != nil || c.Module != mod {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	return c, nil
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
