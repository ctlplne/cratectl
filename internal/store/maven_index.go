// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type MavenIndexFile struct {
	Path, Digest string
	Size         int64
	Modified     time.Time
}

// MavenHostedIndex observes primary JAR references with visible POMs under the
// same current authorization, byte decision and lifecycle snapshot.
func (s *Store) MavenHostedIndex(ctx context.Context, i Identity, repo string, limit int, byteLimit int64) ([]MavenIndexFile, error) {
	if limit < 1 || byteLimit < 1 {
		return nil, ErrMetadataLimit
	}
	limit = min(limit, 10000)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var files []MavenIndexFile
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "maven" || r.Mode != "hosted" {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `SELECT a.path,a.digest,a.size,a.created_at
FROM cratectl.artifacts a
JOIN cratectl.artifacts pom ON (pom.tenant,pom.repository,pom.path)=(a.tenant,a.repository,left(a.path,-4)||'.pom')
`+decisionJoin+nativeLifecycleJoin+`
LEFT JOIN cratectl.content_decisions pd ON (pd.tenant,pd.repository,pd.digest)=(pom.tenant,pom.repository,pom.digest)
LEFT JOIN cratectl.artifact_lifecycle pl ON (pl.tenant,pl.repository,pl.path)=(pom.tenant,pom.repository,pom.path)
WHERE a.tenant=$1 AND a.repository=$2 AND right(a.path,4)='.jar'
 AND octet_length(a.path)<=2048 AND NOT COALESCE(nl.deleted,false) AND NOT COALESCE(pl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND COALESCE(pd.decision,pom.decision)<>'denied'
 AND (NOT $3::boolean OR (COALESCE(d.decision,a.decision)='allowed' AND COALESCE(pd.decision,pom.decision)='allowed'))
ORDER BY a.path COLLATE "C" LIMIT $4`, i.Tenant, r.Name, r.RequireReview, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var file MavenIndexFile
			if err := rows.Scan(&file.Path, &file.Digest, &file.Size, &file.Modified); err != nil {
				return err
			}
			byteLimit -= int64(len(file.Path) + len(file.Digest) + 64)
			if len(files) == limit || byteLimit < 0 {
				return ErrMetadataLimit
			}
			files = append(files, file)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
