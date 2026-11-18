// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"maps"
	"net/textproto"
	"slices"
	"strings"

	pep "github.com/aquasecurity/go-pep440-version"
	"github.com/jackc/pgx/v5"
)

type PythonSearchHit struct {
	Name    string
	Version string
	Summary string
}

type pythonSearchCandidate struct {
	hit     PythonSearchHit
	version pep.Version
}

// PythonSearch searches validated retained files whose current policy and
// lifecycle permit discovery. It does not request an upstream catalog or file.
func (s *Store) PythonSearch(ctx context.Context, i Identity, repo string, names, summaries []string, maxFiles int, maxBytes int64) ([]PythonSearchHit, error) {
	if maxFiles < 1 || maxFiles > 10000 || maxBytes < 1 || maxBytes > 64<<20 ||
		len(names)+len(summaries) < 1 || len(names) > 16 || len(summaries) > 16 {
		return nil, ErrMetadataLimit
	}
	hits := map[string]pythonSearchCandidate{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "pypi" {
			return ErrConflict
		}
		if r.Mode != "hosted" {
			return pythonCachedSearch(ctx, tx, i, r, names, summaries, pythonSearchBudget{files: maxFiles, bytes: maxBytes}, hits)
		}
		rows, err := tx.Query(ctx, `SELECT left(a.metadata->>'name',201),left(a.metadata->>'version',101),
CASE WHEN octet_length(a.metadata->>'core_metadata')<=$3 THEN a.metadata->>'core_metadata' END
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
LEFT JOIN cratectl.python_yanks y ON (y.tenant,y.repository,y.filename)=(a.tenant,a.repository,a.path)
WHERE a.tenant=$1 AND a.repository=$2 AND a.media_type='application/octet-stream'
 AND a.metadata->'archive_validated'='true'::jsonb AND a.metadata->>'filename'=a.path
 AND NOT COALESCE(y.yanked,false) AND NOT COALESCE(nl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY a.path LIMIT $5`, i.Tenant, r.Name, maxBytes, r.RequireReview, maxFiles+1)
		if err != nil {
			return err
		}
		defer rows.Close()

		remaining := maxBytes
		for counted := 0; rows.Next(); counted++ {
			if counted >= maxFiles {
				return ErrMetadataLimit
			}
			var hit PythonSearchHit
			var raw *string
			if err := rows.Scan(&hit.Name, &hit.Version, &raw); err != nil {
				return err
			}
			if raw == nil || int64(len(*raw)) > remaining {
				return ErrMetadataLimit
			}
			remaining -= int64(len(*raw))
			if err := selectPythonSearchHit(hits, hit, *raw, names, summaries); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	result := make([]PythonSearchHit, 0, len(hits))
	for _, candidate := range hits {
		result = append(result, candidate.hit)
	}
	slices.SortFunc(result, func(a, b PythonSearchHit) int { return cmp.Compare(a.Name, b.Name) })
	return result, nil
}

func selectPythonSearchHit(hits map[string]pythonSearchCandidate, hit PythonSearchHit, raw string, names, summaries []string) error {
	headers, err := textproto.NewReader(bufio.NewReader(strings.NewReader(raw))).ReadMIMEHeader()
	if err != nil || hit.Name == "" || len(hit.Name) > 200 || len(hit.Version) > 100 {
		return ErrPythonUnvalidated
	}
	hit.Summary = searchDescription(headers.Get("Summary"))
	if !containsPythonSearchTerm(hit.Name, names) && !containsPythonSearchTerm(hit.Summary, summaries) {
		return nil
	}
	version, err := pep.Parse(hit.Version)
	if err != nil {
		return ErrPythonUnvalidated
	}
	current, present := hits[hit.Name]
	if !present || version.GreaterThan(current.version) {
		hits[hit.Name] = pythonSearchCandidate{hit: hit, version: version}
	}
	if len(hits) > 100 {
		return ErrMetadataLimit
	}
	return nil
}

func pythonCachedSearch(ctx context.Context, tx pgx.Tx, i Identity, endpoint Repository, names, summaries []string, budget pythonSearchBudget, hits map[string]pythonSearchCandidate) error {
	const maxNames = 256
	members := endpoint.Settings.Members
	if endpoint.Mode == "proxy" {
		members = []string{endpoint.Name}
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT left(a.metadata->>'name',201) AS name
FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository)
LEFT JOIN cratectl.repository_grants g ON (g.tenant,g.repository,g.actor)=(a.tenant,a.repository,$3)
WHERE a.tenant=$1 AND a.repository=ANY($2::text[]) AND a.metadata->>'name' IS NOT NULL
 AND ($4::boolean OR r.access='tenant' OR g.can_read)
 AND a.metadata->'archive_validated'='true'::jsonb AND (r.mode='hosted' OR a.source_revision=r.source_revision)
ORDER BY name LIMIT $5`, i.Tenant, members, i.Actor, i.Role == "admin", maxNames+1)
	if err != nil {
		return err
	}
	projects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(projects) > maxNames {
		return ErrMetadataLimit
	}
	for _, project := range projects {
		if project == "" || len(project) > 200 {
			return ErrPythonUnvalidated
		}
		sources, err := pythonViewInTx(ctx, tx, i, endpoint.Name, project, budget.files, budget.bytes, &budget)
		if errors.Is(err, errNativeSearchCatalog) {
			continue
		}
		if err != nil {
			return err
		}
		files := MergePythonMembers(sources)
		for _, name := range slices.Sorted(maps.Keys(files)) {
			selected := files[name].File
			if selected.Blocked || !selected.File.Validated || selected.Digest == "" || selected.File.Yanked != nil {
				continue
			}
			hit := PythonSearchHit{Name: project, Version: selected.File.Version}
			if err := selectPythonSearchHit(hits, hit, selected.File.CoreMetadata, names, summaries); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsPythonSearchTerm(text string, terms []string) bool {
	text = strings.ToLower(text)
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}
