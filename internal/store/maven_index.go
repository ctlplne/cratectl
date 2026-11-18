// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
		if r.Format != "maven" {
			return ErrNotFound
		}
		if r.Mode == "group" {
			files, err = mavenGroupIndex(ctx, tx, i, r, limit, byteLimit)
			return err
		}
		if r.Mode != "hosted" && r.Mode != "proxy" {
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

func mavenGroupIndex(ctx context.Context, tx pgx.Tx, i Identity, endpoint Repository, limit int, byteLimit int64) ([]MavenIndexFile, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT a.path COLLATE "C" AS path
FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository)
LEFT JOIN cratectl.repository_grants g ON (g.tenant,g.repository,g.actor)=(a.tenant,a.repository,$3)
LEFT JOIN cratectl.repository_lifecycle rl ON (rl.tenant,rl.repository)=(a.tenant,a.repository)
`+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1 AND a.repository=ANY($2::text[]) AND r.format='maven'
 AND (r.mode='hosted' OR (r.mode='proxy' AND a.source_revision=r.source_revision))
 AND COALESCE(rl.state,'active')='active' AND ($4::boolean OR r.access='tenant' OR g.can_read)
 AND right(a.path,4)='.jar' AND octet_length(a.path)<=2048
 AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
 AND (NOT (r.require_review OR $5::boolean) OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY path LIMIT $6`, i.Tenant, endpoint.Settings.Members, i.Actor, i.Role == "admin", endpoint.RequireReview, limit+1)
	if err != nil {
		return nil, err
	}
	paths, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(paths) > limit {
		return nil, ErrMetadataLimit
	}
	var files []MavenIndexFile
	sources := map[string]Repository{}
	for _, jarPath := range paths {
		byteLimit -= int64(len(jarPath) + 128)
		if byteLimit < 0 {
			return nil, ErrMetadataLimit
		}
		jar, err := mavenIndexGroupArtifact(ctx, tx, i, endpoint, jarPath, sources)
		if err == nil {
			_, err = mavenIndexGroupArtifact(ctx, tx, i, endpoint, strings.TrimSuffix(jarPath, ".jar")+".pom", sources)
		}
		if nativeSearchSourceUnavailable(err) || errors.Is(err, ErrDeleted) || errors.Is(err, errNativeSearchCatalog) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files = append(files, MavenIndexFile{Path: jar.Path, Digest: jar.Digest, Size: jar.Size, Modified: jar.Created})
	}
	return files, nil
}

// The group can select the JAR and POM from different members. Each path must
// follow the live pull order. Unknown preferred proxy authority fences discovery.
func mavenIndexGroupArtifact(ctx context.Context, tx pgx.Tx, i Identity, endpoint Repository, path string, sources map[string]Repository) (Artifact, error) {
	for _, member := range MembersForPath(endpoint, path) {
		source, present := sources[member]
		if !present {
			var err error
			source, err = repositoryInTx(ctx, tx, i, member, "read")
			if err != nil {
				return Artifact{}, err
			}
			sources[member] = source
		}
		if source.Format != "maven" || source.Mode == "group" {
			return Artifact{}, ErrConflict
		}
		if err := notDeletedInTx(ctx, tx, source.Name, path); err != nil {
			return Artifact{}, err
		}
		if source.Mode == "proxy" {
			state, err := nativeCatalogRetrieval(ctx, tx, source.Name, path)
			if errors.Is(err, pgx.ErrNoRows) {
				return Artifact{}, errNativeSearchCatalog
			}
			if err != nil {
				return Artifact{}, err
			}
			if state.SourceRevision != source.SourceRevision || !state.Fresh() || (state.State != "ready" && state.State != "negative") {
				return Artifact{}, errNativeSearchCatalog
			}
			if state.State == "negative" {
				continue
			}
		}
		budget := repositoryReadBudget(source)
		budget.sqlMetadataBytes = 32 << 10
		a, err := readArtifact(ctx, tx, source.Name, path, source.RequireReview || endpoint.RequireReview, budget)
		if source.Mode == "hosted" && errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return Artifact{}, err
		}
		if source.Mode == "proxy" {
			var binding struct {
				Authority string `json:"source_authority"`
				Path      string `json:"source_path"`
			}
			if json.Unmarshal(a.Metadata, &binding) != nil || source.Settings.Upstream == nil ||
				binding.Authority != source.Settings.Upstream.URL || binding.Path != path {
				return Artifact{}, errNativeSearchCatalog
			}
		}
		return a, nil
	}
	return Artifact{}, ErrNotFound
}
