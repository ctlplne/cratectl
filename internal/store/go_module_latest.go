// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/module"
)

// Latest is a mutable selection as well as a package-byte read. Recheck its
// complete current discovery and exact-byte source/policy/cache selection in
// one repeatable-read snapshot after disk verification, before response headers.
func (s *Store) GoModuleLatestSelectionAtRevision(ctx context.Context, i Identity, endpoint, p string, snapshot SourceSnapshot, limit int, budget int64, admissions ...NativeAdmission) (Artifact, Repository, error) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Operation != "info" || snapshot.Repository == "" || snapshot.Revision < 0 || len(snapshot.Groups) > 1 || len(admissions) > 96 {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	if limit < 1 || limit > 10000 || budget < 1 || budget > 64<<20 {
		return Artifact{}, Repository{}, ErrMetadataLimit
	}
	escaped, e := module.EscapePath(request.Module)
	if e != nil {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	var catalogs, bundles []NativeAdmission
	for _, a := range admissions {
		if strings.HasPrefix(a.Path, "go-catalog/") {
			catalogs = append(catalogs, a)
		} else {
			bundles = append(bundles, a)
		}
	}
	if len(catalogs) > 32 || len(bundles) > 64 {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	var selected Artifact
	var source Repository
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if e := goModuleSelectionInTx(ctx, tx, i, endpoint, p, escaped, request, snapshot, bundles, &selected, &source); e != nil {
			return e
		}
		view := GoModuleVersionView{Versions: []string{}}
		if e := goModuleViewInTx(ctx, tx, i, endpoint, request.Module, escaped, limit, budget, catalogs, &view); e != nil {
			return e
		}
		latest := gomodule.LatestVersion(view.Versions)
		if latest == "" && view.Known {
			return ErrDenied
		}
		if latest != request.Version {
			return ErrConflict
		}
		return nil
	})
	if e != nil {
		return Artifact{}, Repository{}, e
	}
	return selected, source, nil
}
