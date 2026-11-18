// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ociImage = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)

const MaxOCIRepositoryPageSize = 1000

func ValidOCIImage(image string) bool {
	return len(image) <= 255 && ociImage.MatchString(image)
}

func ValidOCIRepositoryName(name string) bool {
	repo, image, ok := strings.Cut(name, "/")
	return ok && Name.MatchString(repo) && ValidOCIImage(image)
}

// OCIRepositoryCatalog advertises names with at least one currently readable
// manifest. A cached proxy graph needs current receipts for every member.
// The database snapshot binds grants, policy and graph reads without upstream IO.
func (s *Store) OCIRepositoryCatalog(ctx context.Context, i Identity, after string, limit int, byteLimit int64) ([]string, string, error) {
	const candidateLimit = 4096
	if limit < 0 || limit > MaxOCIRepositoryPageSize || byteLimit < 1 || (after != "" && !ValidOCIRepositoryName(after)) {
		return nil, "", ErrMetadataLimit
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	names := make([]string, 0, limit)
	next := ""
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if limit == 0 {
			return nil
		}
		const manifestSuffixBytes = len("/manifests/sha256:") + 64
		rows, err := tx.Query(ctx, `SELECT a.repository,a.path,
 (a.repository||'/'||left(a.path,-$5::integer)) COLLATE "C" AS name
FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository)
LEFT JOIN cratectl.repository_grants g ON (g.tenant,g.repository,g.actor)=(a.tenant,a.repository,$2)
LEFT JOIN cratectl.repository_lifecycle rl ON (rl.tenant,rl.repository)=(a.tenant,a.repository)
`+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1 AND r.format='oci' AND COALESCE(rl.state,'active')='active'
 AND (r.mode='hosted' OR (r.mode='proxy' AND a.source_revision=r.source_revision AND EXISTS (
   SELECT 1 FROM cratectl.retrievals rc WHERE (rc.tenant,rc.repository,rc.path,rc.source_revision)=(a.tenant,a.repository,a.path,r.source_revision)
     AND rc.state='ready' AND rc.fresh_until>clock_timestamp())))
 AND ($3::boolean OR r.access='tenant' OR g.can_read)
 AND octet_length(a.repository)<=63 AND octet_length(a.path) BETWEEN $5+1 AND $5+255
 AND right(a.path,$5)='/manifests/sha256:'||a.digest AND a.metadata->'oci_validated'='true'::jsonb
 AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
 AND (NOT r.require_review OR COALESCE(d.decision,a.decision)='allowed')
 AND (a.repository||'/'||left(a.path,-$5::integer)) COLLATE "C">$4
ORDER BY name,a.path COLLATE "C" LIMIT $6`, i.Tenant, i.Actor, i.Role == "admin", after, manifestSuffixBytes, candidateLimit+1)
		if err != nil {
			return err
		}
		type candidate struct{ Repository, Path, Name string }
		candidates, err := pgx.CollectRows(rows, pgx.RowToStructByPos[candidate])
		if err != nil {
			return err
		}
		budget := newGraphBudget()
		budget.metadataBytes = min(budget.metadataBytes, byteLimit)
		budget.sqlMetadataBytes = budget.metadataBytes
		var repo Repository
		for offset, item := range candidates {
			if offset == candidateLimit {
				return ErrMetadataLimit
			}
			if !ValidOCIRepositoryName(item.Name) || (len(names) != 0 && names[len(names)-1] == item.Name) {
				continue
			}
			if item.Repository != repo.Name {
				repo, err = repositoryInTx(ctx, tx, i, item.Repository, "read")
				if err != nil {
					return err
				}
				clear(budget.checked) // Graph paths are meaningful only inside one repository.
				budget.cacheRepository, budget.sourceRevision = "", nil
				if repo.Mode == "proxy" {
					budget.cacheRepository, budget.sourceRevision = repo.Name, &repo.SourceRevision
				}
			}
			artifact, err := readArtifact(ctx, tx, repo.Name, item.Path, repo.RequireReview, budget)
			if errors.Is(err, ErrDenied) || errors.Is(err, ErrDeleted) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrOCIUnvalidated) {
				continue
			}
			if repo.Mode == "proxy" && (errors.Is(err, ErrOCICacheExpired) || errors.Is(err, ErrOCICache) ||
				errors.Is(err, ErrBusy) || errors.Is(err, ErrSourceChanged)) {
				continue
			}
			if err != nil {
				return err
			}
			if !isManifest(artifact.MediaType) {
				continue
			}
			if len(names) == limit {
				next = names[len(names)-1]
				return nil
			}
			names = append(names, item.Name)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return names, next, nil
}
