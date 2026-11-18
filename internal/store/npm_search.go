// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
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

var errNPMSearchCatalog = errors.New("npm search has no current catalog authority")

// NPMSearch selects one currently visible package version per name. A proxy
// result requires retained bytes and a current catalog. Search never fills it.
func (s *Store) NPMSearch(ctx context.Context, i Identity, repo, query string, from, size, budget, maxTags int, maxBytes int64) ([]NPMSearchPackage, int, error) {
	terms := strings.Fields(strings.ToLower(query))
	if len(terms) < 1 || len(terms) > 16 || len(query) > 256 || from < 0 || from > 10000 ||
		size < 0 || size > 100 || budget < 1 || budget > 10000 || maxTags < 1 || maxBytes < 1 {
		return nil, 0, ErrMetadataLimit
	}
	selected := map[string]npmSearchCandidate{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "npm" {
			return ErrConflict
		}
		if r.Mode != "hosted" {
			return npmCachedSearch(ctx, tx, i, r, terms, npmViewBudget{versions: budget, tags: maxTags, bytes: maxBytes}, selected)
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
			candidate.version = version
			selectNPMSearchResult(selected, candidate)
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

func selectNPMSearchResult(selected map[string]npmSearchCandidate, candidate npmSearchCandidate) {
	pkg := &candidate.pkg
	current, exists := selected[pkg.Name]
	if exists {
		if current.latest && !candidate.latest {
			return
		}
		if current.latest == candidate.latest {
			order := candidate.version.Compare(current.version)
			if order < 0 || (order == 0 && pkg.Version >= current.pkg.Version) {
				return
			}
		}
	}
	var description strings.Builder
	for _, r := range pkg.Description {
		if description.Len() >= 512 {
			break
		}
		if !unicode.IsControl(r) {
			description.WriteRune(r)
		}
	}
	pkg.Description = description.String()
	pkg.Maintainers = []struct{}{}
	pkg.Date = pkg.Date.UTC()
	selected[pkg.Name] = candidate
}

func npmCachedSearch(ctx context.Context, tx pgx.Tx, i Identity, endpoint Repository, terms []string, budget npmViewBudget, selected map[string]npmSearchCandidate) error {
	const maxNames = 256
	members := endpoint.Settings.Members
	if endpoint.Mode == "proxy" {
		members = []string{endpoint.Name}
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT left(a.metadata->>'name',215) AS name
FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository)
LEFT JOIN cratectl.repository_grants g ON (g.tenant,g.repository,g.actor)=(a.tenant,a.repository,$3)
WHERE a.tenant=$1 AND a.repository=ANY($2::text[]) AND a.metadata->>'name' IS NOT NULL
 AND ($4::boolean OR r.access='tenant' OR g.can_read)
 AND ((r.mode='hosted' AND a.media_type='application/octet-stream') OR
      (r.mode='proxy' AND a.source_revision=r.source_revision AND a.metadata ? 'source_key'))
 AND NOT EXISTS (SELECT 1 FROM unnest($5::text[]) AS term
                 WHERE strpos(lower((a.metadata->>'name') COLLATE "C"),term)=0)
ORDER BY name LIMIT $6`, i.Tenant, members, i.Actor, i.Role == "admin", terms, maxNames+1)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(names) > maxNames {
		return ErrMetadataLimit
	}
	for _, name := range names {
		if name == "" || len(name) > 214 {
			return ErrConflict
		}
		sources, err := npmViewInTx(ctx, tx, i, endpoint.Name, name, &budget, true)
		if errors.Is(err, errNPMSearchCatalog) {
			continue
		}
		if err != nil {
			return err
		}
		versions, tags := MergeNPMMembers(sources)
		for _, item := range versions {
			v := item.Version
			if v.Blocked || v.created.IsZero() {
				continue
			}
			version, err := semver.StrictNewVersion(v.Version)
			if err != nil || version.String() != v.Version || len(v.Version) > 128 {
				return ErrConflict
			}
			var pkg struct {
				Description json.RawMessage `json:"description"`
			}
			if json.Unmarshal(v.Package, &pkg) != nil {
				return ErrConflict
			}
			var description string
			_ = json.Unmarshal(pkg.Description, &description)
			selectNPMSearchResult(selected, npmSearchCandidate{
				pkg:     NPMSearchPackage{Name: name, Version: v.Version, Description: description, Date: v.created},
				version: version, latest: tags["latest"] == v.Version,
			})
		}
	}
	return nil
}
