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
		rows, err := tx.Query(ctx, `WITH readable AS (
 SELECT r.tenant,r.name,r.mode,r.require_review,r.settings,r.source_revision
 FROM cratectl.repositories r
 LEFT JOIN cratectl.repository_grants g ON (g.tenant,g.repository,g.actor)=(r.tenant,r.name,$2)
 LEFT JOIN cratectl.repository_lifecycle rl ON (rl.tenant,rl.repository)=(r.tenant,r.name)
 WHERE r.tenant=$1 AND r.format='oci' AND COALESCE(rl.state,'active')='active'
   AND ($3::boolean OR r.access='tenant' OR g.can_read) AND octet_length(r.name)<=63
), routes AS (
 SELECT name AS endpoint,name AS member FROM readable WHERE mode<>'group'
 UNION ALL
 SELECT g.name,m.name FROM readable g CROSS JOIN LATERAL jsonb_array_elements_text(g.settings->'members') AS m(name)
 WHERE g.mode='group'
)
SELECT DISTINCT route.endpoint,a.path COLLATE "C" AS path,
 (route.endpoint||'/'||left(a.path,-$5::integer)) COLLATE "C" AS name
FROM cratectl.artifacts a JOIN readable r ON (r.tenant,r.name)=(a.tenant,a.repository)
JOIN routes route ON route.member=r.name
`+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1
 AND (r.mode='hosted' OR (r.mode='proxy' AND a.source_revision=r.source_revision AND EXISTS (
   SELECT 1 FROM cratectl.retrievals rc WHERE (rc.tenant,rc.repository,rc.path,rc.source_revision)=(a.tenant,a.repository,a.path,r.source_revision)
     AND rc.state='ready' AND rc.fresh_until>clock_timestamp())))
 AND octet_length(a.path) BETWEEN $5+1 AND $5+255
 AND right(a.path,$5)='/manifests/sha256:'||a.digest AND a.metadata->'oci_validated'='true'::jsonb
 AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
 AND (NOT r.require_review OR COALESCE(d.decision,a.decision)='allowed')
 AND (route.endpoint||'/'||left(a.path,-$5::integer)) COLLATE "C">$4
ORDER BY name,path LIMIT $6`, i.Tenant, i.Actor, i.Role == "admin", after, manifestSuffixBytes, candidateLimit+1)
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
		reader := ociCatalogGraph{budget: budget}
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
			}
			_, image, _ := strings.Cut(item.Name, "/")
			artifact, err := reader.manifest(ctx, tx, i, repo, image, item.Path)
			if nativeSearchSourceUnavailable(err) || errors.Is(err, ErrDeleted) || errors.Is(err, ErrOCIUnvalidated) {
				continue
			}
			if errors.Is(err, ErrOCICacheExpired) || errors.Is(err, ErrOCICache) || errors.Is(err, ErrBusy) || errors.Is(err, ErrSourceChanged) {
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

type ociCatalogGraph struct {
	budget        *graphBudget
	repository    string
	requireReview bool
}

// The same graph can be admitted through a direct repository and withheld
// through a group with mandatory review. Cache graph reads only within one policy.
func (g *ociCatalogGraph) read(ctx context.Context, tx pgx.Tx, source Repository, path string, review bool) (Artifact, error) {
	if g.repository != source.Name || g.requireReview != review {
		g.repository, g.requireReview = source.Name, review
		clear(g.budget.checked)
		g.budget.cacheRepository, g.budget.sourceRevision = "", nil
		if source.Mode == "proxy" {
			g.budget.cacheRepository, g.budget.sourceRevision = source.Name, &source.SourceRevision
		}
	}
	return readArtifact(ctx, tx, source.Name, path, review, g.budget)
}

// Select an exact digest using the same group authorization, review and member
// order as pulls. A proxy can yield to a lower source only with current exact
// absence evidence. Catalog requests never refresh expired or unknown evidence.
func (g *ociCatalogGraph) manifest(ctx context.Context, tx pgx.Tx, i Identity, endpoint Repository, image, path string) (Artifact, error) {
	if endpoint.Mode != "group" {
		return g.read(ctx, tx, endpoint, path, endpoint.RequireReview)
	}
	_, members, err := nativeRepositories(ctx, tx, i, endpoint.Name, image, "oci")
	if err != nil {
		return Artifact{}, err
	}
	for _, source := range members {
		if err := notDeletedInTx(ctx, tx, source.Name, path); err != nil {
			return Artifact{}, err
		}
		if source.Mode == "proxy" {
			state, err := nativeCatalogRetrieval(ctx, tx, source.Name, path)
			if errors.Is(err, pgx.ErrNoRows) {
				return Artifact{}, ErrOCICacheExpired
			}
			if err != nil {
				return Artifact{}, err
			}
			if state.SourceRevision != source.SourceRevision || !state.Fresh() || (state.State != "ready" && state.State != "negative") {
				return Artifact{}, ErrOCICacheExpired
			}
			if state.State == "negative" {
				continue
			}
		} else {
			var exists bool
			err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, source.Name, path).Scan(&exists)
			if err != nil {
				return Artifact{}, err
			}
			if !exists {
				continue
			}
		}
		return g.read(ctx, tx, source, path, endpoint.RequireReview || source.RequireReview)
	}
	return Artifact{}, ErrNotFound
}
