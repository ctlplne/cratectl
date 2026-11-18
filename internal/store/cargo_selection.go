// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"

	"ctlplne.dev/cratectl/internal/cargo"
	"github.com/jackc/pgx/v5"
)

var ErrCargoUnvalidated = errors.New("stored Cargo archive binding differs")

type CargoGroupRoute struct {
	Repository string
	Revision   int64
	Member     Repository
	Admissions []NativeAdmission
}

type CargoGroupRefresh struct{ Source Repository }

func (e *CargoGroupRefresh) Error() string { return "Cargo group source needs current sparse metadata" }
func (e *CargoGroupRefresh) Unwrap() error { return ErrBusy }

func (s *Store) CargoGroupMember(ctx context.Context, i Identity, repo, name string, revision int64, refreshed map[string]bool, admissions []NativeAdmission) (CargoGroupRoute, error) {
	route := CargoGroupRoute{Repository: repo, Revision: revision, Admissions: admissions}
	prefix, err := cargo.ArtifactPrefix(name)
	if err != nil {
		return route, ErrNotFound
	}
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var e error
		route.Member, _, e = cargoRepositoryInTx(ctx, tx, i, repo, name, prefix, &route, refreshed)
		return e
	})
	return route, err
}

// The first member retaining a crate name owns its complete index, including
// versions that are denied, unassessed or retired. Falling back on any of those
// outcomes would let a lower member replace bytes under an existing lockfile.
func cargoRepositoryInTx(ctx context.Context, tx pgx.Tx, i Identity, repo, name, prefix string, route *CargoGroupRoute, refreshed map[string]bool) (Repository, bool, error) {
	key, err := cargo.NameKey(name)
	if err != nil {
		return Repository{}, false, ErrNotFound
	}
	root, members, err := nativeRepositories(ctx, tx, i, repo, key, "cargo")
	if err != nil {
		return Repository{}, false, err
	}
	if root.Mode == "hosted" {
		if route != nil {
			return Repository{}, false, ErrSourceChanged
		}
		return root, root.RequireReview, nil
	}
	if root.Mode != "group" {
		return Repository{}, false, ErrConflict
	}
	var admissions []NativeAdmission
	if route != nil {
		if root.Name != route.Repository || root.SourceRevision != route.Revision {
			return Repository{}, false, ErrSourceChanged
		}
		admissions = route.Admissions
	}
	for _, member := range members {
		if member.Mode == "proxy" {
			if refreshed != nil && !refreshed[member.Name] {
				return Repository{}, false, &CargoGroupRefresh{Source: member}
			}
			present, e := cargoProxyPresenceInTx(ctx, tx, member, key, admissions)
			if e != nil {
				return Repository{}, false, e
			}
			if !present {
				continue
			}
			return cargoGroupRouteMember(root, member, route)
		}
		if member.Mode != "hosted" {
			return Repository{}, false, ErrConflict
		}
		var spelling *string
		err = tx.QueryRow(ctx, `SELECT left(metadata->>'name',65) FROM cratectl.artifacts
WHERE tenant=$1 AND repository=$2 AND starts_with(path,$3) ORDER BY path LIMIT 1`,
			i.Tenant, member.Name, prefix).Scan(&spelling)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return Repository{}, false, err
		}
		if spelling == nil {
			return Repository{}, false, ErrConflict
		}
		if !strings.EqualFold(*spelling, name) {
			return Repository{}, false, ErrNotFound
		}
		return cargoGroupRouteMember(root, member, route)
	}
	return Repository{}, false, ErrNotFound
}

func cargoGroupRouteMember(root, member Repository, route *CargoGroupRoute) (Repository, bool, error) {
	if route != nil && route.Member.Name != "" && (route.Member.Name != member.Name || route.Member.SourceRevision != member.SourceRevision) {
		return Repository{}, false, ErrConflict
	}
	return member, root.RequireReview || member.RequireReview, nil
}

func cargoProxyPresenceInTx(ctx context.Context, tx pgx.Tx, repo Repository, name string, admissions []NativeAdmission) (bool, error) {
	p := CargoCatalogPath(name)
	state, err := cargoCacheState(ctx, tx, repo, p)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrSourceChanged) {
		return false, &CargoGroupRefresh{Source: repo}
	}
	if err != nil {
		return false, err
	}
	var retained bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, repo.Name, p).Scan(&retained); err != nil {
		return false, err
	}
	if state.State == "negative" {
		current := state.Fresh()
		for _, admitted := range admissions {
			current = current || (admitted.Repository == repo.Name && admitted.Path == p && admitted.Generation == state.Generation && !admitted.Stale)
		}
		if !current {
			return false, &CargoGroupRefresh{Source: repo}
		}
		// Withdrawal from the upstream fences lower copies of a previously
		// retained crate. A source that has never retained this name may yield.
		if retained {
			return false, ErrNotFound
		}
		return false, nil
	}
	admitted, err := cargoCacheAllowed(ctx, tx, repo, state, admissions)
	if err != nil {
		return false, err
	}
	if !admitted {
		return false, &CargoGroupRefresh{Source: repo}
	}
	if !retained {
		return false, ErrCargoUnvalidated
	}
	return true, nil
}

func (s *Store) CargoDownload(ctx context.Context, i Identity, repo, name, version string, routes ...*CargoGroupRoute) (Artifact, Repository, error) {
	var artifact Artifact
	var source Repository
	key, err := cargo.ArtifactPath(name, version)
	if err != nil {
		return artifact, source, ErrNotFound
	}
	prefix, _ := cargo.ArtifactPrefix(name)
	var route *CargoGroupRoute
	if len(routes) > 0 {
		route = routes[0]
	}
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		selected, review, err := cargoRepositoryInTx(ctx, tx, i, repo, name, prefix, route, nil)
		if err != nil {
			return err
		}
		if selected.Mode != "hosted" {
			return ErrConflict
		}
		source = selected
		artifact, err = readArtifact(ctx, tx, source.Name, key, review, repositoryReadBudget(source))
		if err != nil {
			return err
		}
		entry, err := CargoArtifactEntry(artifact)
		if err != nil {
			return ErrCargoUnvalidated
		}
		if !strings.EqualFold(entry.Name, name) || entry.Version != version {
			return ErrNotFound
		}
		return nil
	})
	return artifact, source, err
}
