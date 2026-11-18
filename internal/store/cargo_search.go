// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/cargo"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/semver"
)

type CargoSearchHit struct {
	Name        string `json:"name"`
	Version     string `json:"max_version"`
	Description string `json:"description"`
}

// CargoSearch reads a bounded snapshot of currently discoverable versions. A
// yanked crate remains reachable by its lockfile but cannot be advertised here.
func (s *Store) CargoSearch(ctx context.Context, i Identity, repo, query string, limit int) ([]CargoSearchHit, int, error) {
	if query == "" || len(query) > 256 || !utf8.ValidString(query) ||
		strings.IndexFunc(query, unicode.IsControl) >= 0 || limit < 1 || limit > 100 {
		return nil, 0, cargo.ErrInput
	}
	const candidateLimit = 10000
	query = strings.ToLower(query)
	latest := make(map[string]CargoSearchHit)
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "cargo" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT left(a.path,257),left(a.metadata->>'name',65),
 left(a.metadata->>'vers',129),left(COALESCE(a.metadata->>'description',''),513)
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1 AND a.repository=$2 AND a.media_type=$3 AND a.metadata->>'cksum'=a.digest
 AND strpos(lower((a.metadata->>'name') COLLATE "C"),$4)>0
 AND a.metadata->'yanked'='false'::jsonb AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
 AND (NOT $5::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY a.path LIMIT $6`, i.Tenant, repo, cargo.MediaType, query, r.RequireReview, candidateLimit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for seen := 0; rows.Next(); seen++ {
			if seen >= candidateLimit {
				return ErrMetadataLimit
			}
			var path string
			var hit CargoSearchHit
			if err = rows.Scan(&path, &hit.Name, &hit.Version, &hit.Description); err != nil {
				return err
			}
			key, err := cargo.ArtifactPath(hit.Name, hit.Version)
			if err != nil || path != key || len(hit.Description) > 512 {
				return ErrConflict
			}
			current, ok := latest[hit.Name]
			if !ok || semver.Compare("v"+hit.Version, "v"+current.Version) > 0 {
				latest[hit.Name] = hit
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	hits := slices.Collect(maps.Values(latest))
	slices.SortFunc(hits, func(a, b CargoSearchHit) int {
		aName, bName := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if rank := cmp.Compare(searchRank(aName, query), searchRank(bName, query)); rank != 0 {
			return rank
		}
		return cmp.Compare(aName, bName)
	})
	if len(hits) == 0 {
		return []CargoSearchHit{}, 0, nil
	}
	return hits[:min(len(hits), limit)], len(hits), nil
}

func searchRank(name, query string) int {
	switch {
	case name == query:
		return 0
	case strings.HasPrefix(name, query):
		return 1
	default:
		return 2
	}
}
