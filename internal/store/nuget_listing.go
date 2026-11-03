// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	"ctlplne.dev/cratectl/internal/nuget"
	"github.com/jackc/pgx/v5"
)

// SetNuGetListing changes discovery state, never retires the package reference or
// changes its bytes. Pinned consumers must retain access to unlisted packages.
// The common tenant write fence serializes listing, publication, holds, grants
// and retirement; the event and outbox commit with the metadata change.
func (s *Store) SetNuGetListing(ctx context.Context, i Identity, repo, id, version string, listed bool) error {
	id, e := nuget.IDKey(id)
	if e != nil {
		return ErrNotFound
	}
	version, e = nuget.VersionKey(version)
	if e != nil {
		return ErrNotFound
	}
	path := NuGetPath(id, version)
	_, e = s.MutateRepository(ctx, i, repo, "", "", "nuget.package.listing.changed", func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		a := Artifact{Repository: repo, Path: path}
		// Bound the returned metadata in SQL, including inconsistent records.
		e = tx.QueryRow(ctx, `SELECT left(digest,65),size,left(media_type,129),CASE WHEN octet_length(metadata::text)<=$3 THEN metadata ELSE '{}'::jsonb END FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, path, 2*nuget.MaxNuspecBytes+8192).Scan(&a.Digest, &a.Size, &a.MediaType, &a.Metadata)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		if e != nil {
			return nil, 0, e
		}
		metadata, e := ValidateNuGetArtifact(ctx, a)
		if e != nil {
			return nil, 0, e
		}
		state, e := artifactStateInTx(ctx, tx, repo, path)
		if e != nil {
			return nil, 0, e
		}
		if state.Deleted {
			return nil, 0, ErrDeleted
		}
		changed := metadata.IsListed() != listed
		if changed && state.Held {
			return nil, 0, ErrHeld
		}
		if changed {
			// Preserve the original manifest, its byte binding and unknown fields.
			if _, e = tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{listed}',to_jsonb($3::boolean),true) WHERE repository=$1 AND path=$2`, repo, path, listed); e != nil {
				return nil, 0, e
			}
		}
		return map[string]any{"repository": repo, "path": path, "digest": a.Digest, "listed": listed, "changed": changed, "retained_bytes": true}, 200, nil
	})
	return e
}
