// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/Masterminds/semver/v3"
	"github.com/jackc/pgx/v5"
)

type NPMSearchPackage struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Date        time.Time  `json:"date"`
	Maintainers []struct{} `json:"maintainers"`
}

type npmSearchCandidate struct {
	pkg     NPMSearchPackage
	version *semver.Version
	latest  bool
}

// NPMSearchHosted selects one currently visible package version per name.
// The latest dist-tag takes precedence only when its target is admissible.
func (s *Store) NPMSearchHosted(ctx context.Context, i Identity, repo, query string, from, size, budget int) ([]NPMSearchPackage, int, error) {
	terms := strings.Fields(strings.ToLower(query))
	if len(terms) < 1 || len(terms) > 16 || len(query) > 256 || from < 0 || from > 10000 ||
		size < 0 || size > 100 || budget < 1 || budget > 10000 {
		return nil, 0, ErrMetadataLimit
	}
	selected := map[string]npmSearchCandidate{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "npm" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT left(a.path,600),left(a.metadata->>'name',215),
left(a.metadata->>'version',129),CASE WHEN jsonb_typeof(a.metadata#>'{package,description}')='string'
 THEN left(a.metadata#>>'{package,description}',512) ELSE '' END,
a.created_at,t.version IS NOT NULL
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
LEFT JOIN cratectl.npm_tags t ON (t.tenant,t.repository,t.package,t.version) =
(a.tenant,a.repository,a.metadata->>'name',a.metadata->>'version') AND t.tag='latest' AND NOT t.deleted
WHERE a.tenant=$1 AND a.repository=$2 AND a.media_type='application/octet-stream'
 AND jsonb_typeof(a.metadata#>'{package,dist}')='object'
 AND NOT EXISTS (SELECT 1 FROM unnest($3::text[]) AS term
                 WHERE strpos(lower((a.metadata->>'name') COLLATE "C"),term)=0)
 AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
 AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY a.path LIMIT $5`, i.Tenant, r.Name, terms, r.RequireReview, budget+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for n := 0; rows.Next(); n++ {
			if n >= budget {
				return ErrMetadataLimit
			}
			var path string
			var candidate npmSearchCandidate
			pkg := &candidate.pkg
			if err := rows.Scan(&path, &pkg.Name, &pkg.Version, &pkg.Description, &pkg.Date, &candidate.latest); err != nil {
				return err
			}
			version, err := semver.StrictNewVersion(pkg.Version)
			if err != nil || version.String() != pkg.Version || len(pkg.Name) > 214 || len(pkg.Version) > 128 || path != NPMPath(pkg.Name, pkg.Version) {
				return ErrConflict
			}
			pkg.Description = strings.Map(func(r rune) rune {
				if unicode.IsControl(r) {
					return -1
				}
				return r
			}, pkg.Description)
			pkg.Maintainers = []struct{}{}
			pkg.Date = pkg.Date.UTC()
			candidate.version = version
			current, exists := selected[pkg.Name]
			if !exists || (candidate.latest && !current.latest) ||
				(candidate.latest == current.latest && version.GreaterThan(current.version)) {
				selected[pkg.Name] = candidate
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}

	names := slices.Collect(maps.Keys(selected))
	ranking := strings.ToLower(strings.Join(strings.Fields(query), " "))
	slices.SortFunc(names, func(a, b string) int {
		if rank := cmp.Compare(searchRank(a, ranking), searchRank(b, ranking)); rank != 0 {
			return rank
		}
		return cmp.Compare(a, b)
	})
	total := len(names)
	start := min(from, total)
	out := make([]NPMSearchPackage, 0, min(size, total-start))
	for _, name := range names[start:min(start+size, total)] {
		out = append(out, selected[name].pkg)
	}
	return out, total, nil
}
