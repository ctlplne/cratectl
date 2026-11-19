// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"ctlplne.dev/cratectl/internal/debian"
	"github.com/jackc/pgx/v5"
)

const DebianMedia = "application/vnd.debian.binary-package"
const debianMetadataLimit = (debian.MaxControlBytes+2)/3*4 + 1024

type DebianPackage struct {
	Control   []byte `json:"control"`
	Validated bool   `json:"archive_validated"`
}

func ValidateDebianArtifact(a Artifact) (debian.Control, error) {
	var metadata DebianPackage
	if len(a.Metadata) > debianMetadataLimit || json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated ||
		a.MediaType != DebianMedia || a.Size < 1 || a.Size > debian.MaxArchiveBytes || !uploadDigest.MatchString(a.Digest) {
		return debian.Control{}, ErrConflict
	}
	control, err := debian.ParseControl(metadata.Control)
	if err != nil || control.PoolPath() != a.Path {
		return debian.Control{}, ErrConflict
	}
	return control, nil
}

func (s *Store) PublishDebian(ctx context.Context, i Identity, repo string, a Artifact) error {
	control, err := ValidateDebianArtifact(a)
	if err != nil {
		return err
	}
	_, err = s.MutateRepository(ctx, i, repo, "", "", "apt.package.published", func(tx pgx.Tx) (any, int, error) {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return nil, 0, err
		}
		if r.Format != "apt" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		if !r.Settings.DebianDistribution.SupportsArchitecture(control.Architecture) {
			return nil, 0, ErrConflict
		}
		if err := InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); err != nil {
			return nil, 0, err
		}
		return map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size}, 201, nil
	})
	return err
}

// DebianPackageIndex binds every advertised stanza to the current reference,
// digest decision and retained lifecycle in one tenant read snapshot.
func (s *Store) DebianPackageIndex(ctx context.Context, i Identity, repo, arch string, limit int, byteLimit int64) ([]byte, error) {
	var index []byte
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		index, err = debianPackageIndexInTx(ctx, tx, i, r, arch, limit, byteLimit)
		return err
	})
	return index, err
}

func debianPackageIndexInTx(ctx context.Context, tx pgx.Tx, i Identity, r Repository, arch string, limit int, byteLimit int64) ([]byte, error) {
	if limit < 1 || byteLimit < 1 {
		return nil, ErrMetadataLimit
	}
	if r.Format != "apt" || r.Mode != "hosted" {
		return nil, ErrConflict
	}
	distribution := r.Settings.DebianDistribution
	if (distribution == nil) != (arch == "") || (distribution != nil && (arch == "all" || !distribution.SupportsArchitecture(arch))) {
		return nil, ErrNotFound
	}
	limit = min(limit, 10000)
	byteLimit = min(byteLimit, 8<<20)
	var output strings.Builder
	rows, err := tx.Query(ctx, `SELECT left(a.path,2049),left(a.digest,65),a.size,
CASE WHEN octet_length(a.metadata::text)<=$6 THEN a.metadata ELSE NULL END
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1 AND a.repository=$2 AND a.media_type=$3 AND NOT COALESCE(nl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed')
 AND ($7='' OR split_part(a.path,'/',4) IN ($7,'all'))
ORDER BY a.path COLLATE "C" LIMIT $5`, i.Tenant, r.Name, DebianMedia, r.RequireReview, limit+1, debianMetadataLimit, arch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for count := 0; rows.Next(); count++ {
		if count == limit {
			return nil, ErrMetadataLimit
		}
		a := Artifact{MediaType: DebianMedia}
		if err := rows.Scan(&a.Path, &a.Digest, &a.Size, &a.Metadata); err != nil {
			return nil, err
		}
		control, err := ValidateDebianArtifact(a)
		if err != nil {
			return nil, err
		}
		size := strconv.FormatInt(a.Size, 10)
		fields := "Filename: " + a.Path + "\nSize: " + size + "\nSHA256: " + a.Digest + "\n\n"
		if int64(output.Len()+len(control.Stanza)+len(fields)) > byteLimit {
			return nil, ErrMetadataLimit
		}
		output.WriteString(control.Stanza)
		output.WriteString(fields)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return []byte(output.String()), nil
}
