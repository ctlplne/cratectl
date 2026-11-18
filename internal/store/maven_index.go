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

// MavenRepositoryIndex observes primary JAR references with visible POMs under
// one authorization and policy snapshot. Proxy results require current local
// receipts for both files. Index requests never fetch their upstream.
func (s *Store) MavenRepositoryIndex(ctx context.Context, i Identity, repo string, limit int, byteLimit int64) ([]MavenIndexFile, error) {
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
		if r.Format != "maven" || (r.Mode != "hosted" && r.Mode != "proxy") {
			return ErrNotFound
		}
		authority := ""
		if r.Settings.Upstream != nil {
			authority = r.Settings.Upstream.URL
		}
		rows, err := tx.Query(ctx, `SELECT a.path,a.digest,a.size,a.created_at
FROM cratectl.artifacts a
JOIN cratectl.artifacts pom ON (pom.tenant,pom.repository,pom.path)=(a.tenant,a.repository,left(a.path,-4)||'.pom')
`+decisionJoin+nativeLifecycleJoin+`
LEFT JOIN cratectl.content_decisions pd ON (pd.tenant,pd.repository,pd.digest)=(pom.tenant,pom.repository,pom.digest)
LEFT JOIN cratectl.artifact_lifecycle pl ON (pl.tenant,pl.repository,pl.path)=(pom.tenant,pom.repository,pom.path)
LEFT JOIN cratectl.retrievals jr ON (jr.tenant,jr.repository,jr.path)=(a.tenant,a.repository,a.path)
LEFT JOIN cratectl.retrievals pr ON (pr.tenant,pr.repository,pr.path)=(pom.tenant,pom.repository,pom.path)
WHERE a.tenant=$1 AND a.repository=$2 AND right(a.path,4)='.jar'
 AND octet_length(a.path)<=2048 AND NOT COALESCE(nl.deleted,false) AND NOT COALESCE(pl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND COALESCE(pd.decision,pom.decision)<>'denied'
 AND (NOT $3::boolean OR (COALESCE(d.decision,a.decision)='allowed' AND COALESCE(pd.decision,pom.decision)='allowed'))
 AND ($4::boolean OR (a.source_revision=$5 AND pom.source_revision=$5 AND jr.source_revision=$5 AND pr.source_revision=$5
   AND jr.state='ready' AND pr.state='ready' AND jr.fresh_until>clock_timestamp() AND pr.fresh_until>clock_timestamp()
   AND a.metadata->>'source_authority'=$6 AND pom.metadata->>'source_authority'=$6
   AND a.metadata->>'source_path'=a.path AND pom.metadata->>'source_path'=pom.path))
ORDER BY a.path COLLATE "C" LIMIT $7`, i.Tenant, r.Name, r.RequireReview, r.Mode == "hosted", r.SourceRevision, authority, limit+1)
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
