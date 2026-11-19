// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"ctlplne.dev/cratectl/internal/composer"
	"github.com/jackc/pgx/v5"
)

type ComposerSearchHit struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ComposerSearch returns one visible reference per package. The newest
// matching retained version supplies the description for text search.
func (s *Store) ComposerSearch(ctx context.Context, i Identity, repo, query, pattern string, budget int, byteLimit int64) ([]ComposerSearchHit, error) {
	terms := strings.Fields(strings.ToLower(query))
	if len(query) > 256 || len(terms) > 16 || len(pattern) > 512 || (len(terms) == 0) == (pattern == "") ||
		budget < 1 || byteLimit < 1 {
		return nil, ErrMetadataLimit
	}
	budget = min(budget, 10000)
	hits := []ComposerSearchHit{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "composer" || r.Mode != "hosted" {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `WITH visible AS (
 SELECT left(a.path,261) AS path, left(a.metadata#>>'{package,name}',215) AS name,
 left(a.metadata#>>'{package,version}',37) AS version,
 COALESCE(left(a.metadata#>>'{package,description}',513),'') AS description, a.created_at
 FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
 WHERE a.repository=$1 AND a.media_type=$2 AND starts_with(a.path,'dist/')
 AND a.metadata->>'archive_validated'='true' AND NOT COALESCE(nl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $3::boolean OR COALESCE(d.decision,a.decision)='allowed')
), matched AS (
 SELECT DISTINCT ON (name COLLATE "C") path,name,version,description FROM visible
 WHERE ($4<>'' AND name COLLATE "C" LIKE $4)
    OR ($4='' AND NOT EXISTS (SELECT 1 FROM unnest($5::text[]) AS term
       WHERE strpos(lower((name||' '||description) COLLATE "C"),term)=0))
 ORDER BY name COLLATE "C",created_at DESC,path COLLATE "C"
)
SELECT path,name,version,description FROM matched ORDER BY name COLLATE "C" LIMIT $6`,
			repo, ComposerMedia, r.RequireReview, pattern, terms, budget+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if len(hits) >= budget {
				return ErrMetadataLimit
			}
			var path, version string
			var hit ComposerSearchHit
			if err := rows.Scan(&path, &hit.Name, &version, &hit.Description); err != nil {
				return err
			}
			coordinate, valid := composer.ParseDistribution(path)
			if !valid || coordinate.Name != hit.Name || coordinate.Version != version {
				return ErrConflict
			}
			byteLimit -= int64(len(hit.Name) + len(hit.Description))
			if byteLimit < 0 {
				return ErrMetadataLimit
			}
			hits = append(hits, hit)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if pattern == "" {
		ranking := strings.ToLower(query)
		slices.SortFunc(hits, func(a, b ComposerSearchHit) int {
			if rank := cmp.Compare(searchRank(a.Name, ranking), searchRank(b.Name, ranking)); rank != 0 {
				return rank
			}
			return cmp.Compare(a.Name, b.Name)
		})
	}
	return hits, nil
}
