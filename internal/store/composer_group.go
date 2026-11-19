// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"

	"ctlplne.dev/cratectl/internal/composer"
	"github.com/jackc/pgx/v5"
)

// composerSourceInTx selects the first member retaining any version of the
// package. Withdrawn and denied versions still reserve the package identity.
func composerSourceInTx(ctx context.Context, tx pgx.Tx, i Identity, endpoint Repository, name string) (Repository, error) {
	if endpoint.Format != "composer" {
		return Repository{}, ErrConflict
	}
	if endpoint.Mode == "hosted" {
		return endpoint, nil
	}
	if endpoint.Mode != "group" {
		return Repository{}, ErrConflict
	}
	for _, member := range MembersForPath(endpoint, name+"/") {
		source, err := repositoryInTx(ctx, tx, i, member, "read")
		if err != nil {
			return Repository{}, err
		}
		if source.Format != "composer" || source.Mode != "hosted" {
			return Repository{}, ErrConflict
		}
		var owns bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND starts_with(path,$2))`,
			source.Name, "dist/"+name+"/").Scan(&owns)
		if err != nil {
			return Repository{}, err
		}
		if owns {
			return source, nil
		}
	}
	return Repository{}, ErrNotFound
}

// ComposerGroupArtifact binds the advertised digest to the currently owning
// member and the current read policy in one snapshot.
func (s *Store) ComposerGroupArtifact(ctx context.Context, i Identity, repo, path, digest string, revision int64) (Artifact, Repository, error) {
	coordinate, ok := composer.ParseDistribution(path)
	if !ok || !uploadDigest.MatchString(digest) {
		return Artifact{}, Repository{}, ErrNotFound
	}
	var artifact Artifact
	var source Repository
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		endpoint, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if endpoint.SourceRevision != revision || endpoint.Mode != "group" {
			return ErrSourceChanged
		}
		source, err = composerSourceInTx(ctx, tx, i, endpoint, coordinate.Name)
		if err != nil {
			return err
		}
		budget := repositoryReadBudget(source)
		budget.sqlMetadataBytes = composerMetadataBytes
		artifact, err = readArtifact(ctx, tx, source.Name, path, endpoint.RequireReview || source.RequireReview, budget)
		if err != nil {
			return err
		}
		if artifact.Digest != digest {
			return ErrConflict
		}
		_, err = decodeComposerPackage(artifact)
		return err
	})
	return artifact, source, err
}
