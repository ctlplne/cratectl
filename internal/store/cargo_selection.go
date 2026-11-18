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

// The first member retaining a crate name owns its complete index, including
// versions that are denied, unassessed or retired. Falling back on any of those
// outcomes would let a lower member replace bytes under an existing lockfile.
func cargoRepositoryInTx(ctx context.Context, tx pgx.Tx, i Identity, repo, name, prefix string) (Repository, bool, error) {
	key, err := cargo.NameKey(name)
	if err != nil {
		return Repository{}, false, ErrNotFound
	}
	root, members, err := nativeRepositories(ctx, tx, i, repo, key, "cargo")
	if err != nil {
		return Repository{}, false, err
	}
	if root.Mode == "hosted" {
		return root, root.RequireReview, nil
	}
	if root.Mode != "group" {
		return Repository{}, false, ErrConflict
	}
	for _, member := range members {
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
		return member, root.RequireReview || member.RequireReview, nil
	}
	return Repository{}, false, ErrNotFound
}

func (s *Store) CargoDownload(ctx context.Context, i Identity, repo, name, version string) (Artifact, Repository, error) {
	var artifact Artifact
	var source Repository
	key, err := cargo.ArtifactPath(name, version)
	if err != nil {
		return artifact, source, ErrNotFound
	}
	prefix, _ := cargo.ArtifactPrefix(name)
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		selected, review, err := cargoRepositoryInTx(ctx, tx, i, repo, name, prefix)
		if err != nil {
			return err
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
