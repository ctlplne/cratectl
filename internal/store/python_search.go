// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bufio"
	"cmp"
	"context"
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

// PythonHostedSearch searches validated hosted files whose current policy and
// lifecycle permit discovery. The newest matching non-yanked version wins.
func (s *Store) PythonHostedSearch(ctx context.Context, i Identity, repo string, names, summaries []string, maxFiles int, maxBytes int64) ([]PythonSearchHit, error) {
	const maxProjects = 100
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
		if r.Format != "pypi" || r.Mode != "hosted" {
			return ErrConflict
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
			headers, err := textproto.NewReader(bufio.NewReader(strings.NewReader(*raw))).ReadMIMEHeader()
			if err != nil || hit.Name == "" || len(hit.Name) > 200 || len(hit.Version) > 100 {
				return ErrPythonUnvalidated
			}
			hit.Summary = searchDescription(headers.Get("Summary"))
			if !containsPythonSearchTerm(hit.Name, names) && !containsPythonSearchTerm(hit.Summary, summaries) {
				continue
			}
			version, err := pep.Parse(hit.Version)
			if err != nil {
				return ErrPythonUnvalidated
			}
			current, present := hits[hit.Name]
			if !present || version.GreaterThan(current.version) {
				hits[hit.Name] = pythonSearchCandidate{hit: hit, version: version}
			}
			if len(hits) > maxProjects {
				return ErrMetadataLimit
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

func containsPythonSearchTerm(text string, terms []string) bool {
	text = strings.ToLower(text)
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}
