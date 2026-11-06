// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// GoModuleLatestView preserves complete discovery policy while using current
// optional hints for proxy pseudos only when no allowed tagged version exists.
// Ordinary version lists never require the optional upstream latest endpoint.
func (s *Store) GoModuleLatestView(ctx context.Context, i Identity, repo, mod string, limit int, budget int64, admissions ...NativeAdmission) (GoModuleVersionView, error) {
	escaped, e := module.EscapePath(mod)
	if e != nil || len(mod) > gomodule.MaxModulePath || limit < 1 || limit > 10000 || budget < 1 || budget > 64<<20 || len(admissions) > 64 {
		return GoModuleVersionView{}, ErrMetadataLimit
	}
	catalogs, hints := 0, 0
	for _, a := range admissions {
		switch {
		case strings.HasPrefix(a.Path, "go-catalog/"):
			catalogs++
		case strings.HasPrefix(a.Path, "go-latest/"):
			hints++
		default:
			return GoModuleVersionView{}, ErrGoModuleUnvalidated
		}
	}
	if catalogs > 32 || hints > 32 {
		return GoModuleVersionView{}, ErrGoModuleUnvalidated
	}
	view := GoModuleVersionView{Versions: []string{}}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		return goModuleViewInTx(ctx, tx, i, repo, mod, escaped, limit, budget, admissions, &view, true)
	})
	if e != nil {
		return GoModuleVersionView{}, e
	}
	semver.Sort(view.Versions)
	return view, nil
}

// Latest is a mutable selection as well as a package-byte read. Recheck its
// complete current discovery and exact-byte source/policy/cache selection in
// one repeatable-read snapshot after disk verification, before response headers.
func (s *Store) GoModuleLatestSelectionAtRevision(ctx context.Context, i Identity, endpoint, p string, snapshot SourceSnapshot, limit int, budget int64, admissions ...NativeAdmission) (Artifact, Repository, error) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Operation != "info" || snapshot.Repository == "" || snapshot.Revision < 0 || len(snapshot.Groups) > 1 || len(admissions) > 128 {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	if limit < 1 || limit > 10000 || budget < 1 || budget > 64<<20 {
		return Artifact{}, Repository{}, ErrMetadataLimit
	}
	escaped, e := module.EscapePath(request.Module)
	if e != nil {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	var catalogs, hints, bundles []NativeAdmission
	for _, a := range admissions {
		if strings.HasPrefix(a.Path, "go-catalog/") {
			catalogs = append(catalogs, a)
		} else if strings.HasPrefix(a.Path, "go-latest/") {
			hints = append(hints, a)
		} else {
			bundles = append(bundles, a)
		}
	}
	if len(catalogs) > 32 || len(hints) > 32 || len(bundles) > 64 {
		return Artifact{}, Repository{}, ErrGoModuleUnvalidated
	}
	var selected Artifact
	var source Repository
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if e := goModuleSelectionInTx(ctx, tx, i, endpoint, p, escaped, request, snapshot, bundles, &selected, &source); e != nil {
			return e
		}
		view := GoModuleVersionView{Versions: []string{}}
		if e := goModuleViewInTx(ctx, tx, i, endpoint, request.Module, escaped, limit, budget, append(catalogs, hints...), &view, true); e != nil {
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
