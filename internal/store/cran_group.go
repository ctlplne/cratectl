// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"strings"

	"ctlplne.dev/cratectl/internal/cran"
	"github.com/jackc/pgx/v5"
)

func cranGroupInTx(ctx context.Context, tx pgx.Tx, i Identity, repo string, revision int64) (Repository, map[string]Repository, error) {
	group, err := repositoryInTx(ctx, tx, i, repo, "read")
	if err != nil {
		return Repository{}, nil, err
	}
	if group.Format != "cran" || group.Mode != "group" || group.SourceRevision != revision {
		return Repository{}, nil, ErrSourceChanged
	}
	if len(group.Settings.Members) < 1 || len(group.Settings.Members) > 32 {
		return Repository{}, nil, ErrConflict
	}
	sources := make(map[string]Repository, len(group.Settings.Members))
	for _, name := range group.Settings.Members {
		source, err := repositoryInTx(ctx, tx, i, name, "read")
		if err != nil {
			return Repository{}, nil, err
		}
		if source.Mode != "hosted" || source.Format != "cran" {
			return Repository{}, nil, ErrConflict
		}
		sources[name] = source
	}
	return group, sources, nil
}

// CRANGroupIndex assigns a package to its first retaining member before
// filtering versions. A denied or retired preferred row still claims its name.
// The stock Repository column uses the index's digest-bound Path field.
func (s *Store) CRANGroupIndex(ctx context.Context, i Identity, repo string, revision int64, limit int, byteLimit int64) (string, error) {
	if limit < 1 || byteLimit < 1 {
		return "", ErrMetadataLimit
	}
	limit, byteLimit = min(limit, 10000), min(byteLimit, 8<<20)
	var body strings.Builder
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		group, sources, err := cranGroupInTx(ctx, tx, i, repo, revision)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT a.repository,left(a.path,257),left(a.digest,65),a.size,
CASE WHEN octet_length(a.metadata::text)<=$6 THEN a.metadata ELSE NULL END,
COALESCE(d.decision,a.decision),COALESCE(nl.deleted,false)
FROM unnest($1::text[]) WITH ORDINALITY AS m(name,position)
JOIN cratectl.artifacts a ON a.tenant=$2 AND a.repository=m.name `+decisionJoin+nativeLifecycleJoin+`
WHERE starts_with(a.path,$3) AND a.media_type=$4
ORDER BY m.position,a.path COLLATE "C" LIMIT $5`, group.Settings.Members, i.Tenant,
			cran.SourceDirectory, CRANMedia, limit+1, cranMetadataLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		owners := make(map[string]string)
		for count := 0; rows.Next(); count++ {
			if count == limit {
				return ErrMetadataLimit
			}
			a := Artifact{MediaType: CRANMedia}
			var deleted bool
			if err := rows.Scan(&a.Repository, &a.Path, &a.Digest, &a.Size, &a.Metadata, &a.Decision, &deleted); err != nil {
				return err
			}
			metadata, err := ValidateCRANArtifact(a)
			if err != nil {
				return err
			}
			name := metadata.Description["Package"]
			owner := group.Settings.NamespaceOwners[name+"/"]
			if owner == "" {
				owner = owners[name]
				if owner == "" {
					owner = a.Repository
					owners[name] = owner
				}
			}
			if owner != a.Repository || deleted || a.Decision == "denied" ||
				((group.RequireReview || sources[a.Repository].RequireReview) && a.Decision != "allowed") {
				continue
			}
			entry := metadata.Description.IndexEntry(metadata.MD5, a.Digest)
			if int64(body.Len()+len(entry)) > byteLimit {
				return ErrMetadataLimit
			}
			body.WriteString(entry)
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	return body.String(), nil
}

// CRANGroupArtifact binds a stock download locator to the current owner,
// current group and member policy, and the exact advertised SHA-256.
func (s *Store) CRANGroupArtifact(ctx context.Context, i Identity, repo, path, digest string, revision int64) (Artifact, Repository, error) {
	coordinate, valid := cran.ParsePath(path)
	if !valid || !uploadDigest.MatchString(digest) {
		return Artifact{}, Repository{}, ErrNotFound
	}
	var file Artifact
	var selected Repository
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		group, sources, err := cranGroupInTx(ctx, tx, i, repo, revision)
		if err != nil {
			return err
		}
		for _, member := range MembersForPath(group, coordinate.Name+"/") {
			source := sources[member]
			var retains bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts
WHERE tenant=$1 AND repository=$2 AND starts_with(path,$3) AND media_type=$4)`,
				i.Tenant, member, cran.SourceDirectory+coordinate.Name+"_", CRANMedia).Scan(&retains); err != nil {
				return err
			}
			if !retains {
				continue
			}
			selected = source
			budget := repositoryReadBudget(source)
			budget.sqlMetadataBytes = cranMetadataLimit
			file, err = readArtifact(ctx, tx, member, path, group.RequireReview || source.RequireReview, budget)
			if err != nil {
				return err
			}
			if file.Digest != digest {
				return ErrConflict
			}
			_, err = ValidateCRANArtifact(file)
			return err
		}
		return ErrNotFound
	})
	return file, selected, err
}
