// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"slices"

	"ctlplne.dev/cratectl/internal/nuget"
	"github.com/jackc/pgx/v5"
)

// NuGetGroupRefresh identifies the next consulted proxy whose package-wide
// catalog must be read before any lower source can be considered.
type NuGetGroupRefresh struct{ Source Repository }

func (*NuGetGroupRefresh) Error() string {
	return "NuGet group requires current proxy catalog authority"
}

type NuGetGroupView struct {
	Source   Repository
	Versions []string
}

type nugetGroupSelection struct {
	source  Repository
	review  bool
	catalog NuGetProxyCatalog
}

func nugetGroupSource(ctx context.Context, tx pgx.Tx, i Identity, group, id string, revision int64, limit int, byteLimit int64,
	refreshed map[string]bool, admissions []NativeAdmission) (nugetGroupSelection, error) {
	root, err := repositoryInTx(ctx, tx, i, group, "read")
	if err != nil {
		return nugetGroupSelection{}, err
	}
	if root.Format != "nuget" || root.Mode != "group" || revision != root.SourceRevision {
		return nugetGroupSelection{}, ErrSourceChanged
	}
	for _, member := range MembersForPath(root, id+"/") {
		source, err := repositoryInTx(ctx, tx, i, member, "read")
		if err != nil {
			return nugetGroupSelection{}, err
		}
		selected := nugetGroupSelection{source: source, review: root.RequireReview || source.RequireReview}
		if source.Format != "nuget" {
			return selected, ErrConflict
		}
		switch source.Mode {
		case "hosted":
			// Retained, denied and unlisted coordinates still establish who owns
			// the package ID. Filtering them cannot open a lower source.
			exists, err := hasNuGetGroupReference(ctx, tx, i, source, id)
			if err != nil || exists {
				return selected, err
			}
		case "proxy":
			if source.Settings.Upstream == nil {
				return selected, ErrSourceChanged
			}
			if refreshed != nil && !refreshed[member] {
				return selected, &NuGetGroupRefresh{Source: source}
			}
			path := NuGetProxyCatalogPath(id)
			state, err := nativeCatalogRetrieval(ctx, tx, source.Name, path)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return selected, err
			}
			if state.SourceRevision != source.SourceRevision || (!state.Fresh() && !nugetAdmitted(state, admissions, false)) || (state.State != "ready" && state.State != "negative") {
				return selected, &NuGetGroupRefresh{Source: source}
			}
			if state.State == "negative" {
				// A retained package still reserves this ID at the current
				// source revision. Temporary upstream removal cannot route
				// around an existing policy decision or tombstone.
				exists, err := hasNuGetGroupReference(ctx, tx, i, source, id)
				if err != nil || exists {
					return selected, err
				}
				continue
			}
			a, err := nativeCatalogArtifact(ctx, tx, i, source.Name, id, "nuget", NuGetProxyCatalogMedia)
			if err != nil {
				return selected, err
			}
			selected.catalog, err = decodeNuGetProxyCatalog(ctx, a.Metadata, id, source.Settings.Upstream.URL, min(limit, 10000), min(byteLimit, 8<<20))
			if err != nil || len(selected.catalog.Versions) != 0 {
				return selected, err
			}
			exists, err := hasNuGetGroupReference(ctx, tx, i, source, id)
			if err != nil || exists {
				return selected, err
			}
		default:
			return selected, ErrConflict
		}
	}
	return nugetGroupSelection{}, ErrNotFound
}

func hasNuGetGroupReference(ctx context.Context, tx pgx.Tx, i Identity, r Repository, id string) (bool, error) {
	var found bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE tenant=$1 AND repository=$2
AND starts_with(path,$3) AND ($4::boolean OR source_revision=$5))`,
		i.Tenant, r.Name, "nuget-packages/"+id+"/", r.Mode == "hosted", r.SourceRevision).Scan(&found)
	return found, err
}

func (s *Store) NuGetGroupVersions(ctx context.Context, i Identity, group, id, version string, revision int64,
	limit int, byteLimit int64, refreshed map[string]bool, admissions ...NativeAdmission) (NuGetGroupView, error) {
	key, err := nuget.IDKey(id)
	if err != nil || key != id || limit < 1 || limit > nuget.MaxOrderedVersions || byteLimit < 1 || len(admissions) > 32 {
		return NuGetGroupView{}, ErrMetadataLimit
	}
	if version != "" {
		if normalized, err := nuget.VersionKey(version); err != nil || normalized != version {
			return NuGetGroupView{}, ErrNotFound
		}
	}
	var view NuGetGroupView
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		selected, err := nugetGroupSource(ctx, tx, i, group, id, revision, limit, byteLimit, refreshed, admissions)
		if err != nil {
			return err
		}
		view.Source = selected.source
		if version != "" {
			if selected.source.Mode == "proxy" && !slices.Contains(selected.catalog.Versions, version) {
				return ErrNotFound
			}
			return nil
		}
		if selected.source.Mode == "proxy" {
			if len(selected.catalog.Versions) != 0 {
				view.Versions, err = nugetProxyVersionsInTx(ctx, tx, i, selected.source, selected.catalog, selected.review)
			}
		} else {
			view.Versions, err = nugetHostedVersionsInTx(ctx, tx, selected.source.Name, id, selected.review, limit, byteLimit)
		}
		return err
	})
	if err == nil && version == "" && view.Source.Mode == "hosted" {
		view.Versions, err = nuget.SortVersionKeys(ctx, view.Versions)
	}
	return view, err
}

// NuGetGroupArtifact reselects package ownership and current grants in the
// same snapshot as the archive read, after the caller verifies the blob.
func (s *Store) NuGetGroupArtifact(ctx context.Context, i Identity, group string, selected SourceSnapshot, path string,
	limit int, byteLimit int64, admissions ...NativeAdmission) (Artifact, error) {
	coordinate, err := ParseNuGetProxyCoordinate(path)
	var artifact Artifact
	if err != nil || coordinate.Version == "" || len(selected.Groups) != 1 || len(admissions) > 33 {
		return artifact, ErrNuGetUnvalidated
	}
	revision, ok := selected.Groups[group]
	if !ok {
		return artifact, ErrSourceChanged
	}
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		current, err := nugetGroupSource(ctx, tx, i, group, coordinate.ID, revision, limit, byteLimit, nil, admissions)
		var refresh *NuGetGroupRefresh
		if errors.As(err, &refresh) || errors.Is(err, ErrNotFound) {
			return ErrSourceChanged
		}
		if err != nil {
			return err
		}
		source := current.source
		if source.Name != selected.Repository || source.SourceRevision != selected.Revision ||
			(source.Mode == "proxy" && !slices.Contains(current.catalog.Versions, coordinate.Version)) {
			return ErrSourceChanged
		}
		artifact, err = nugetArchiveInTx(ctx, tx, source, path, current.review, admissions)
		return err
	})
	return artifact, err
}
