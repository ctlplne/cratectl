// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"cmp"
	"context"
	"errors"
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
	query = strings.ToLower(query)
	latest := make(map[string]CargoSearchHit)
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "cargo" {
			return ErrConflict
		}
		if r.Mode == "hosted" {
			_, err = cargoHostedSearch(ctx, tx, i, r, query, false, 10000, latest)
			return err
		}
		return cargoCachedSearch(ctx, tx, i, r, query, latest)
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

func cargoHostedSearch(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, query string, exact bool, budget int, latest map[string]CargoSearchHit) (int, error) {
	rows, err := tx.Query(ctx, `SELECT left(a.path,257),left(a.metadata->>'name',65),
 left(a.metadata->>'vers',129),left(COALESCE(a.metadata->>'description',''),513)
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.tenant=$1 AND a.repository=$2 AND a.media_type=$3 AND a.metadata->>'cksum'=a.digest
 AND (CASE WHEN $7::boolean THEN lower((a.metadata->>'name') COLLATE "C")=$4 ELSE strpos(lower((a.metadata->>'name') COLLATE "C"),$4)>0 END)
 AND a.metadata->'yanked'='false'::jsonb AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
 AND (NOT $5::boolean OR COALESCE(d.decision,a.decision)='allowed')
	ORDER BY a.path LIMIT $6`, i.Tenant, repo.Name, cargo.MediaType, query, repo.RequireReview, budget+1, exact)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		if seen >= budget {
			return seen, ErrMetadataLimit
		}
		seen++
		var path string
		var hit CargoSearchHit
		if err = rows.Scan(&path, &hit.Name, &hit.Version, &hit.Description); err != nil {
			return seen, err
		}
		key, err := cargo.ArtifactPath(hit.Name, hit.Version)
		if err != nil || path != key || len(hit.Description) > 512 {
			return seen, ErrConflict
		}
		selectCargoSearchHit(latest, hit)
	}
	return seen, rows.Err()
}

func selectCargoSearchHit(latest map[string]CargoSearchHit, hit CargoSearchHit) {
	current, ok := latest[hit.Name]
	if !ok || semver.Compare("v"+hit.Version, "v"+current.Version) > 0 {
		latest[hit.Name] = hit
	}
}

func cargoCachedSearch(ctx context.Context, tx pgx.Tx, i Identity, r Repository, query string, latest map[string]CargoSearchHit) error {
	const nameLimit = 256
	members := r.Settings.Members
	if r.Mode == "proxy" {
		members = []string{r.Name}
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT left(lower((a.metadata->>'name') COLLATE "C"),65) AS name
FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository)
LEFT JOIN cratectl.repository_grants g ON (g.tenant,g.repository,g.actor)=(a.tenant,a.repository,$3)
WHERE a.tenant=$1 AND a.repository=ANY($2::text[]) AND a.media_type=$5
AND ($4::boolean OR r.access='tenant' OR g.can_read)
AND (r.mode='hosted' OR a.source_revision=r.source_revision)
AND strpos(lower((a.metadata->>'name') COLLATE "C"),$6)>0
ORDER BY name LIMIT $7`, i.Tenant, members, i.Actor, i.Role == "admin", cargo.MediaType, query, nameLimit+1)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(names) > nameLimit {
		return ErrMetadataLimit
	}
	versions, metadata := 10000, int64(8<<20)
	for _, name := range names {
		source := r
		if r.Mode == "group" {
			prefix, e := cargo.ArtifactPrefix(name)
			if e != nil {
				return ErrCargoUnvalidated
			}
			selected, review, e := cargoRepositoryInTx(ctx, tx, i, r.Name, name, prefix, nil, nil)
			if searchCargoUnavailable(e) {
				continue
			}
			if e != nil {
				return e
			}
			source = selected
			source.RequireReview = review
		}
		var seen int
		var err error
		if source.Mode == "hosted" {
			seen, err = cargoHostedSearch(ctx, tx, i, source, name, true, versions, latest)
		} else {
			seen, err = cargoProxySearch(ctx, tx, source, name, versions, &metadata, latest)
		}
		if !searchCargoUnavailable(err) && err != nil {
			return err
		}
		versions -= seen
	}
	return nil
}

func cargoProxySearch(ctx context.Context, tx pgx.Tx, r Repository, name string, limit int, budget *int64, latest map[string]CargoSearchHit) (int, error) {
	if err := cargoCacheInTx(ctx, tx, r, CargoCatalogPath(name), nil); err != nil {
		return 0, err
	}
	a, catalog, err := cargoCatalogInTx(ctx, tx, r, name, *budget)
	if err != nil {
		return 0, err
	}
	*budget -= int64(len(a.Metadata))
	if len(catalog.Entries) > limit {
		return 0, ErrMetadataLimit
	}
	paths, digests, err := cargoCatalogPaths(catalog, name)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT p.position,left(COALESCE(a.metadata->>'description',''),513)
FROM unnest($1::text[],$2::text[]) WITH ORDINALITY AS p(path,digest,position)
JOIN cratectl.artifacts a ON (a.repository,a.path,a.source_revision,a.digest)=($3,p.path,$4,p.digest) `+decisionJoin+nativeLifecycleJoin+`
WHERE a.media_type=$5 AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'
AND (NOT $6::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY p.position LIMIT $7`, paths, digests, r.Name, r.SourceRevision, cargo.MediaType, r.RequireReview, limit+1)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var pos int
		var description string
		if err := rows.Scan(&pos, &description); err != nil {
			return 0, err
		}
		if pos < 1 || pos > len(catalog.Entries) || len(description) > 512 {
			return 0, ErrCargoUnvalidated
		}
		row := catalog.Entries[pos-1]
		if !row.Yanked {
			selectCargoSearchHit(latest, CargoSearchHit{Name: row.Name, Version: row.Version, Description: description})
		}
	}
	return len(catalog.Entries), rows.Err()
}

func searchCargoUnavailable(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrDenied) || errors.Is(err, ErrBusy) || errors.Is(err, ErrDeleted) ||
		errors.Is(err, ErrRepositorySuspended) || errors.Is(err, ErrRepositoryRemoved)
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
