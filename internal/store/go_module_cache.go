// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

var ErrGoModuleCacheExpired = errors.New("Go module bundle cache requires revalidation")

// Validate receipts against the last complete bundle, not just the current
// attempt's generation. A transient failed refresh has a newer attempt number
// but may admit the preceding complete bundle through an explicit stale admission.
func validateGoModuleCacheReceipts(repo Repository, c gomodule.Coordinate, receipts []Retrieval) error {
	if len(receipts) != 3 || c.Prefix() == "" {
		return ErrGoModuleUnvalidated
	}
	root := receipts[0]
	p := c.Prefix() + ".zip"
	if root.Path != p || root.ValidationRoot != p || root.ValidationGeneration <= 0 || root.ValidationGeneration > root.Generation {
		return ErrGoModuleUnvalidated
	}
	if root.State == "ready" && root.ValidationGeneration != root.Generation {
		return ErrGoModuleUnvalidated
	}
	for n, kind := range []string{"zip", "mod", "info"} {
		r := receipts[n]
		if r.Repository != repo.Name || r.Path != c.Prefix()+"."+kind || r.SourceRevision != repo.SourceRevision {
			return ErrSourceChanged
		}
		if r.ValidationRoot != p || r.ValidationGeneration != root.ValidationGeneration {
			return ErrGoModuleUnvalidated
		}
	}
	return nil
}

func goModuleCacheReceiptsInTx(ctx context.Context, tx pgx.Tx, repo Repository, c gomodule.Coordinate) error {
	receipts := make([]Retrieval, 0, 3)
	for _, kind := range []string{"zip", "mod", "info"} {
		var r Retrieval
		e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo.Name, c.Prefix()+"."+kind), &r)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrGoModuleCacheExpired
		}
		if e != nil {
			return e
		}
		receipts = append(receipts, r)
	}
	return validateGoModuleCacheReceipts(repo, c, receipts)
}

// GoModuleProxyArtifact admits one cached representation and its complete
// sibling bundle under a single current tenant/grant/source/policy/cache snapshot.
// Call again after object verification immediately before serving response
// headers. This proxy-only foundation does not select group precedence, fill a
// miss, accept catalogs, or enable the public Go adapter.
func (s *Store) GoModuleProxyArtifact(ctx context.Context, i Identity, repo, p string, revision int64, admissions ...NativeAdmission) (Artifact, error) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Version == "" || revision < 0 || len(admissions) > 1 {
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
		a, e = goModuleProxyArtifactInTx(ctx, tx, r, p, request.Coordinate, r.RequireReview, admissions)
		return e
	})
	if e != nil {
		return Artifact{}, e
	}
	return a, nil
}

func goModuleProxyArtifactInTx(ctx context.Context, tx pgx.Tx, r Repository, p string, c gomodule.Coordinate, review bool, admissions []NativeAdmission) (Artifact, error) {
	if r.Settings.GoChecksumAuthority != nil || r.Settings.Cache.RequireChecksum {
		return Artifact{}, ErrGoModuleUnvalidated
	}
	if e := goModuleCacheReceiptsInTx(ctx, tx, r, c); e != nil {
		return Artifact{}, e
	}
	b := repositoryReadBudget(r)
	b.cacheRepository, b.admissions = r.Name, admissions
	a, e := readArtifact(ctx, tx, r.Name, p, review, b)
	if errors.Is(e, ErrNotFound) {
		// The complete receipts witness prior publication, even if every
		// artifact reference has since been lost. Never authorize fallback.
		e = ErrGoModuleUnvalidated
	}
	if e == nil {
		e = checkGoModuleBundle(ctx, tx, r.Name, a, review, b)
	}
	if errors.Is(e, ErrOCICacheExpired) || errors.Is(e, ErrOCICache) {
		e = ErrGoModuleCacheExpired
	}
	if e != nil {
		return Artifact{}, e
	}
	return a, nil
}
