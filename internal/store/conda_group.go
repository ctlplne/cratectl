// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"ctlplne.dev/cratectl/internal/conda"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type condaGroupEntry struct {
	repository, path, digest string
}

var ErrCondaSnapshotChanged = errors.New("Conda group snapshot changed")

// Read ownership across all platforms, including retained denied or retired
// references. Source precedence is by package name, not by individual build.
func currentCondaGroup(ctx context.Context, tx pgx.Tx, i Identity, group Repository, sources map[string]Repository,
	subdir string, limit int) ([]condaGroupEntry, string, error) {
	if limit < 1 {
		return nil, "", ErrMetadataLimit
	}
	limit = min(limit, 10000)
	rows, err := tx.Query(ctx, `SELECT a.repository,left(a.path,321),left(a.digest,65),
 COALESCE(d.decision,a.decision),COALESCE(nl.deleted,false)
FROM unnest($1::text[]) WITH ORDINALITY AS m(name,position)
JOIN cratectl.artifacts a ON (a.tenant,a.repository)=($2,m.name) `+decisionJoin+nativeLifecycleJoin+`
WHERE a.media_type=$3
ORDER BY m.position,a.path COLLATE "C" LIMIT $4`, group.Settings.Members, i.Tenant, CondaMedia, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	owners := make(map[string]string)
	entries := make([]condaGroupEntry, 0)
	for n := 0; rows.Next(); n++ {
		if n == limit {
			return nil, "", ErrMetadataLimit
		}
		var entry condaGroupEntry
		var decision string
		var deleted bool
		if err := rows.Scan(&entry.repository, &entry.path, &entry.digest, &decision, &deleted); err != nil {
			return nil, "", err
		}
		coordinate, valid := conda.ParsePath(entry.path)
		if !valid || !uploadDigest.MatchString(entry.digest) {
			return nil, "", ErrConflict
		}
		owner := group.Settings.NamespaceOwners[coordinate.Name+"/"]
		if owner == "" {
			owner = owners[coordinate.Name]
			if owner == "" {
				owner = entry.repository
				owners[coordinate.Name] = owner
			}
		}
		if owner == entry.repository && coordinate.Subdir == subdir && !deleted && decision != "denied" &&
			(!(group.RequireReview || sources[owner].RequireReview) || decision == "allowed") {
			entries = append(entries, entry)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	slices.SortFunc(entries, func(a, b condaGroupEntry) int { return cmp.Compare(a.path, b.path) })
	hash := crypt.SHA256()
	fmt.Fprintln(hash, "cratectl-conda-group-v1", group.Name, group.SourceRevision, subdir)
	for _, entry := range entries {
		fmt.Fprintln(hash, entry.repository, sources[entry.repository].SourceRevision, entry.path, entry.digest)
	}
	return entries, hex.EncodeToString(hash.Sum(nil)), nil
}

// CondaGroupRepodata uses Conda's v2 base_url to pin the current platform view.
// The filename in each package record remains the stock filename.
func (s *Store) CondaGroupRepodata(ctx context.Context, i Identity, repo, subdir, channelURL string, revision int64, limit int, byteLimit int64) (string, error) {
	if !conda.ValidSubdir(subdir) {
		return "", ErrNotFound
	}
	var output string
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		group, sources, err := hostedGroupInTx(ctx, tx, i, repo, "conda", revision)
		if err != nil {
			return err
		}
		entries, digest, err := currentCondaGroup(ctx, tx, i, group, sources, subdir, limit)
		if err != nil {
			return err
		}
		index, err := newCondaIndex(subdir, channelURL+subdir+"/snapshot/"+digest+"/", byteLimit)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			if err := addCondaGroupRecords(ctx, tx, i, index, entries); err != nil {
				return err
			}
		}
		output = index.finish()
		return nil
	})
	return output, err
}

func addCondaGroupRecords(ctx context.Context, tx pgx.Tx, i Identity, index *condaIndex, entries []condaGroupEntry) error {
	repos, paths := make([]string, 0, len(entries)), make([]string, 0, len(entries))
	for _, entry := range entries {
		repos = append(repos, entry.repository)
		paths = append(paths, entry.path)
	}
	rows, err := tx.Query(ctx, `SELECT a.path,left(a.digest,65),a.size,
 CASE WHEN octet_length(a.metadata::text)<=$4 THEN a.metadata ELSE NULL END
FROM unnest($1::text[],$2::text[]) WITH ORDINALITY AS m(repo,path,position)
JOIN cratectl.artifacts a ON (a.tenant,a.repository,a.path)=($3,m.repo,m.path)
ORDER BY m.position`, repos, paths, i.Tenant, condaMetadataLimit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		a := Artifact{MediaType: CondaMedia}
		if err := rows.Scan(&a.Path, &a.Digest, &a.Size, &a.Metadata); err != nil {
			return err
		}
		if err := index.add(a); err != nil {
			return err
		}
	}
	return rows.Err()
}

// CondaGroupArtifact checks a client's snapshot and exact selected package in
// one read transaction. Call it again after hashing bytes to fence concurrent
// changes to source ownership, grants or review decisions.
func (s *Store) CondaGroupArtifact(ctx context.Context, i Identity, repo, path, expected string, revision int64, limit int) (Artifact, Repository, error) {
	coordinate, valid := conda.ParsePath(path)
	if !valid || !uploadDigest.MatchString(expected) {
		return Artifact{}, Repository{}, ErrNotFound
	}
	var artifact Artifact
	var source Repository
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		group, sources, err := hostedGroupInTx(ctx, tx, i, repo, "conda", revision)
		if err != nil {
			return err
		}
		entries, digest, err := currentCondaGroup(ctx, tx, i, group, sources, coordinate.Subdir, limit)
		if err != nil {
			return err
		}
		if digest != expected {
			return ErrCondaSnapshotChanged
		}
		position, found := slices.BinarySearchFunc(entries, path, func(entry condaGroupEntry, path string) int { return cmp.Compare(entry.path, path) })
		if !found {
			return ErrNotFound
		}
		selected := entries[position]
		source = sources[selected.repository]
		budget := repositoryReadBudget(source)
		budget.sqlMetadataBytes = condaMetadataLimit
		artifact, err = readArtifact(ctx, tx, source.Name, path, group.RequireReview || source.RequireReview, budget)
		if err != nil {
			return err
		}
		if artifact.Digest != selected.digest {
			return ErrConflict
		}
		_, err = ValidateCondaArtifact(artifact)
		return err
	})
	return artifact, source, err
}
