// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"regexp"

	"ctlplne.dev/cratectl/internal/composer"
	"github.com/jackc/pgx/v5"
)

const ComposerMedia = "application/zip"
const composerMetadataBytes = 2 * composer.ManifestBytes

var composerSHA1 = regexp.MustCompile(`^[a-f0-9]{40}$`)

type ComposerPackage struct {
	Package   composer.Package `json:"package"`
	SHA1      string           `json:"shasum"`
	Validated bool             `json:"archive_validated"`
}

func decodeComposerPackage(a Artifact) (ComposerPackage, error) {
	var metadata ComposerPackage
	coordinate, ok := composer.ParseDistribution(a.Path)
	if !ok || a.MediaType != ComposerMedia || !uploadDigest.MatchString(a.Digest) ||
		a.Size < 1 || a.Size > composer.UploadBytes || len(a.Metadata) > composerMetadataBytes ||
		json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated ||
		!composerSHA1.MatchString(metadata.SHA1) || metadata.Package.Version != coordinate.Version ||
		metadata.Package.Type != "library" || !metadata.Package.ValidFor(coordinate) {
		return ComposerPackage{}, ErrConflict
	}
	return metadata, nil
}

func (s *Store) PublishComposer(ctx context.Context, i Identity, repo string, a Artifact) error {
	if _, err := decodeComposerPackage(a); err != nil {
		return err
	}
	_, err := s.MutateRepository(ctx, i, repo, "", "", "composer.package.published", func(tx pgx.Tx) (any, int, error) {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return nil, 0, err
		}
		if r.Format != "composer" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		if err := InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); err != nil {
			return nil, 0, err
		}
		return map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size}, 201, nil
	})
	return err
}

type ComposerDistribution struct {
	Path, Digest string
	Metadata     ComposerPackage
}

// ComposerVersions uses one current authorized read snapshot for all versions.
// Each selected row and the complete metadata response have independent limits.
func (s *Store) ComposerVersions(ctx context.Context, i Identity, repo, name string, revision int64, limit int, byteLimit int64) ([]ComposerDistribution, error) {
	if !composer.ValidName(name) {
		return nil, ErrNotFound
	}
	if limit < 1 || byteLimit < 1 {
		return nil, ErrMetadataLimit
	}
	limit = min(limit, 10000)
	byteLimit = min(byteLimit, 8<<20)
	out := []ComposerDistribution{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.SourceRevision != revision {
			return ErrSourceChanged
		}
		source, err := composerSourceInTx(ctx, tx, i, r, name)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT left(a.path,257),left(a.digest,65),a.size,a.media_type,
CASE WHEN octet_length(a.metadata::text)<=$6 THEN a.metadata ELSE NULL END
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.repository=$1 AND starts_with(a.path,$2) AND a.media_type=$3 AND NOT COALESCE(nl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY a.path COLLATE "C" LIMIT $5`, source.Name, "dist/"+name+"/", ComposerMedia,
			r.RequireReview || source.RequireReview, limit+1, composerMetadataBytes)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if len(out) == limit {
				return ErrMetadataLimit
			}
			var a Artifact
			if err := rows.Scan(&a.Path, &a.Digest, &a.Size, &a.MediaType, &a.Metadata); err != nil {
				return err
			}
			byteLimit -= int64(len(a.Metadata))
			if byteLimit < 0 || len(a.Metadata) == 0 {
				return ErrMetadataLimit
			}
			metadata, err := decodeComposerPackage(a)
			if err != nil {
				return err
			}
			out = append(out, ComposerDistribution{Path: a.Path, Digest: a.Digest, Metadata: metadata})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(out) == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
