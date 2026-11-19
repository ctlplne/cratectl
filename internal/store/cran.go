// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json/v2"
	"regexp"
	"strings"

	"ctlplne.dev/cratectl/internal/cran"
	"github.com/jackc/pgx/v5"
)

const CRANMedia = "application/gzip"
const cranMetadataLimit = 2 * cran.MaxDescriptionBytes

var cranMD5 = regexp.MustCompile(`^[a-f0-9]{32}$`)

type CRANPackage struct {
	Description cran.Package `json:"description"`
	MD5         string       `json:"md5"`
	Validated   bool         `json:"archive_validated"`
}

func ValidateCRANArtifact(a Artifact) (CRANPackage, error) {
	coordinate, ok := cran.ParsePath(a.Path)
	var packageInfo CRANPackage
	if !ok || a.MediaType != CRANMedia || a.Size < 1 || a.Size > cran.MaxArchiveBytes || !uploadDigest.MatchString(a.Digest) ||
		len(a.Metadata) > cranMetadataLimit || json.Unmarshal(a.Metadata, &packageInfo) != nil || !packageInfo.Validated ||
		!packageInfo.Description.ValidFor(coordinate) || !cranMD5.MatchString(packageInfo.MD5) {
		return CRANPackage{}, ErrConflict
	}
	return packageInfo, nil
}

func (s *Store) PublishCRAN(ctx context.Context, i Identity, repo string, a Artifact) error {
	if _, err := ValidateCRANArtifact(a); err != nil {
		return err
	}
	_, err := s.MutateRepository(ctx, i, repo, "", "", "cran.package.published", func(tx pgx.Tx) (any, int, error) {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return nil, 0, err
		}
		if r.Format != "cran" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		if err := InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); err != nil {
			return nil, 0, err
		}
		return map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size}, 201, nil
	})
	return err
}

// CRANPackageIndex reads the current scoped source channel. Each row and the
// complete DCF body are independently bounded before response admission.
func (s *Store) CRANPackageIndex(ctx context.Context, i Identity, repo string, limit int, byteLimit int64) (string, error) {
	if limit < 1 || byteLimit < 1 {
		return "", ErrMetadataLimit
	}
	limit = min(limit, 10000)
	byteLimit = min(byteLimit, 8<<20)
	var output strings.Builder
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "cran" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT left(a.path,257),left(a.digest,65),a.size,
CASE WHEN octet_length(a.metadata::text)<=$6 THEN a.metadata ELSE NULL END
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.repository=$1 AND starts_with(a.path,$2) AND a.media_type=$3 AND NOT COALESCE(nl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY a.path COLLATE "C" LIMIT $5`, repo, cran.SourceDirectory, CRANMedia, r.RequireReview, limit+1, cranMetadataLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for count := 0; rows.Next(); count++ {
			if count == limit {
				return ErrMetadataLimit
			}
			a := Artifact{MediaType: CRANMedia}
			if err := rows.Scan(&a.Path, &a.Digest, &a.Size, &a.Metadata); err != nil {
				return err
			}
			metadata, err := ValidateCRANArtifact(a)
			if err != nil {
				return err
			}
			entry := metadata.Description.IndexEntry(metadata.MD5)
			if int64(output.Len()+len(entry)) > byteLimit {
				return ErrMetadataLimit
			}
			output.WriteString(entry)
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	return output.String(), nil
}
