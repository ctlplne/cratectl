// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"ctlplne.dev/cratectl/internal/cargo"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var cargoDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func CargoArtifactEntry(a Artifact) (cargo.Entry, error) {
	var entry cargo.Entry
	if a.MediaType != cargo.MediaType || a.Size <= 0 || a.Size > cargo.MaxUploadBytes ||
		len(a.Metadata) > 2*cargo.MaxIndexBytes || !cargoDigest.MatchString(a.Digest) ||
		json.Unmarshal(a.Metadata, &entry) != nil || entry.Checksum != a.Digest ||
		entry.Features == nil || entry.Dependencies == nil || entry.Published != "" {
		return cargo.Entry{}, ErrConflict
	}
	p, err := cargo.ArtifactPath(entry.Name, entry.Version)
	if err != nil || p != a.Path {
		return cargo.Entry{}, ErrConflict
	}
	return entry, nil
}

func (s *Store) PublishCargo(ctx context.Context, i Identity, repo string, a Artifact, entry cargo.Entry) error {
	var err error
	entry.Checksum = a.Digest
	a.Metadata, err = json.Marshal(entry)
	if err != nil || len(a.Metadata) > cargo.MaxIndexBytes {
		return ErrMetadataLimit
	}
	if _, err = CargoArtifactEntry(a); err != nil {
		return err
	}
	prefix, _ := cargo.ArtifactPrefix(entry.Name)
	crateKey, _ := cargo.CollisionKey(entry.Name)
	// Same actor, repository and normalized coordinate replay only these bytes.
	// The write grant and retirement fence apply on the replay path too.
	key := "cargo-publish:" + crypt.Digest([]byte(repo+"\x00"+a.Path))
	check := func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return err
		}
		if r.Format != "cargo" || r.Mode != "hosted" {
			return ErrConflict
		}
		if err = requireCargoOwner(ctx, tx, i, repo, crateKey); err != nil {
			return err
		}
		return notDeletedInTx(ctx, tx, repo, a.Path)
	}
	_, err = s.mutateIntentChecked(ctx, i, key, a.Digest, "cargo.crate.published", true, check, func(tx pgx.Tx) (any, int, error) {
		// Hold the common tenant mutation lock across the name and version
		// checks, the artifact insert, and its journal and worker intents.
		var existing *string
		err := tx.QueryRow(ctx, `SELECT left(metadata->>'name',65) FROM cratectl.artifacts
WHERE tenant=$1 AND repository=$2 AND starts_with(path,$3) ORDER BY path LIMIT 1`, i.Tenant, repo, prefix).Scan(&existing)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, err
		}
		if err == nil && (existing == nil || *existing != entry.Name) {
			return nil, 0, ErrConflict
		}
		firstPublication := errors.Is(err, pgx.ErrNoRows)
		var versionExists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE tenant=$1 AND repository=$2 AND path=$3)`,
			i.Tenant, repo, a.Path).Scan(&versionExists); err != nil {
			return nil, 0, err
		}
		if versionExists {
			return nil, 0, ErrConflict
		}
		if err = InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); err != nil {
			return nil, 0, err
		}
		if firstPublication {
			if err = addCargoOwner(ctx, tx, i.Tenant, repo, crateKey, i.Actor); err != nil {
				return nil, 0, err
			}
		}
		return map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size}, 200, nil
	})
	return err
}

// CargoIndex builds one complete newline-delimited index file in a current
// repository-grant and policy snapshot. Oversized results fail as a unit.
func (s *Store) CargoIndex(ctx context.Context, i Identity, repo, name string, limit int, maxBytes int64) ([]byte, error) {
	prefix, err := cargo.ArtifactPrefix(name)
	if err != nil || limit < 1 || limit > 10000 || maxBytes < 1 || maxBytes > 32<<20 {
		return nil, ErrMetadataLimit
	}
	var out []byte
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "cargo" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT a.path,a.digest,a.size,a.media_type,
CASE WHEN octet_length(a.metadata::text)<=$5 THEN a.metadata ELSE NULL END,a.created_at
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1 AND a.repository=$2 AND starts_with(a.path,$3)
AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed') ORDER BY a.path LIMIT $6`,
			i.Tenant, repo, prefix, r.RequireReview, 2*cargo.MaxIndexBytes, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for count := 0; rows.Next(); count++ {
			if count >= limit {
				return ErrMetadataLimit
			}
			var a Artifact
			if err = rows.Scan(&a.Path, &a.Digest, &a.Size, &a.MediaType, &a.Metadata, &a.Created); err != nil {
				return err
			}
			entry, err := CargoArtifactEntry(a)
			if err != nil {
				return err
			}
			if strings.ToLower(entry.Name) != name {
				// A dash/underscore spelling collision occupies the same storage
				// namespace, but has no index file under this spelling.
				return ErrNotFound
			}
			entry.Published = a.Created.UTC().Format("2006-01-02T15:04:05Z")
			entry.Description = ""
			row, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			if int64(len(out)+len(row)+1) > maxBytes {
				return ErrMetadataLimit
			}
			out = append(out, row...)
			out = append(out, '\n')
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// SetCargoYanked changes resolution metadata while retaining the exact archive.
// Cargo lockfiles can still fetch a yanked version through normal byte policy.
func (s *Store) SetCargoYanked(ctx context.Context, i Identity, repo, name, version string, yanked bool) error {
	key, err := cargo.ArtifactPath(name, version)
	if err != nil {
		return ErrNotFound
	}
	crateKey, _ := cargo.CollisionKey(name)
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return err
		}
		if r.Format != "cargo" || r.Mode != "hosted" {
			return ErrConflict
		}
		if err = requireCargoOwner(ctx, tx, i, repo, crateKey); err != nil {
			return err
		}
		a := Artifact{Repository: repo, Path: key}
		err = tx.QueryRow(ctx, `SELECT left(digest,65),size,left(media_type,129),
CASE WHEN octet_length(metadata::text)<=$4 THEN metadata ELSE NULL END
FROM cratectl.artifacts WHERE tenant=$1 AND repository=$2 AND path=$3`,
			i.Tenant, repo, key, 2*cargo.MaxIndexBytes).Scan(&a.Digest, &a.Size, &a.MediaType, &a.Metadata)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		entry, err := CargoArtifactEntry(a)
		if err != nil {
			return err
		}
		if !strings.EqualFold(entry.Name, name) || entry.Version != version {
			return ErrNotFound
		}
		state, err := artifactStateInTx(ctx, tx, repo, key)
		if err != nil {
			return err
		}
		if state.Deleted {
			return ErrDeleted
		}
		if entry.Yanked == yanked {
			return nil
		}
		if state.Held {
			return ErrHeld
		}
		update, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{yanked}',to_jsonb($5::boolean))
WHERE tenant=$1 AND repository=$2 AND path=$3 AND digest=$4`, i.Tenant, repo, key, a.Digest, yanked)
		if err != nil {
			return err
		}
		if update.RowsAffected() != 1 {
			return ErrConflict
		}
		return appendEvent(ctx, tx, i, "cargo.crate.yank.changed", map[string]any{
			"repository": repo, "path": key, "digest": a.Digest, "yanked": yanked,
		})
	})
}
