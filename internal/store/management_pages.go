// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

type ListRequest struct {
	MetadataBytes int
	Key, Query    string
	Before        bool
	Limit         int
	Summary       bool
}
type ListWindow struct {
	First, Last string
	More        bool
}

func (p ListRequest) metadataBudget() int {
	if p.MetadataBytes == 0 {
		return 8 << 20
	}
	return p.MetadataBytes
}
func (p ListRequest) Validate() error {
	if p.metadataBudget() < 1024 || p.metadataBudget() > 64<<20 {
		return ErrConflict
	}
	if p.Limit < 1 || p.Limit > 1000 || len(p.Key) > 2048 || len(p.Query) > 256 || !utf8.ValidString(p.Key) || !utf8.ValidString(p.Query) || strings.ContainsRune(p.Key, 0) || strings.IndexFunc(p.Query, unicode.IsControl) >= 0 || p.Before && p.Key == "" {
		return ErrConflict
	}
	return nil
}
func trimPage[T any](rows []T, req ListRequest, key func(T) string) ([]T, ListWindow) {
	window := ListWindow{More: len(rows) > req.Limit}
	if window.More {
		rows = rows[:req.Limit]
	}
	if len(rows) > 0 {
		window.First = key(rows[0])
		window.Last = key(rows[len(rows)-1])
	}
	if req.Before {
		slices.Reverse(rows)
		window.First, window.Last = window.Last, window.First
	}
	return rows, window
}
func (s *Store) RepositoryPage(ctx context.Context, i Identity, req ListRequest) ([]Repository, ListWindow, error) {
	out := []Repository{}
	window := ListWindow{}
	if req.Validate() != nil || req.Key != "" && !Name.MatchString(req.Key) {
		return out, window, ErrConflict
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT r.name,r.format,r.mode,r.require_review,r.access,CASE WHEN $1 THEN r.settings ELSE '{}'::jsonb END FROM cratectl.repositories r WHERE ($1 OR r.access='tenant' OR EXISTS(SELECT 1 FROM cratectl.repository_grants g WHERE (g.tenant,g.repository,g.actor)=(r.tenant,r.name,$2) AND g.can_read)) AND r.name COLLATE "C" `+compare+` $3 COLLATE "C" AND (r.name||' '||r.format||' '||r.mode) COLLATE "C" ~ $4 ORDER BY r.name COLLATE "C" `+order+` LIMIT $5`, i.Role == "admin", i.Actor, req.Key, literalSearch(req.Query), req.Limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		bytes := 0
		for rows.Next() {
			var r Repository
			var settings []byte
			if e = rows.Scan(&r.Name, &r.Format, &r.Mode, &r.RequireReview, &r.Access, &settings); e != nil {
				return e
			}
			if json.Unmarshal(settings, &r.Settings) != nil {
				return errors.New("invalid durable repository configuration")
			}
			if len(settings) > req.metadataBudget() && len(out) == 0 {
				return ErrMetadataLimit
			}
			bytes += len(settings)
			out = append(out, r)
			if bytes > req.metadataBudget() && len(out) > 1 {
				break
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		// One lookahead is retained to avoid requiring a final empty page. A byte
		// budget can shorten a page; its lookahead is not discarded from traversal.
		actual := req
		if len(out) <= req.Limit && bytes > req.metadataBudget() && len(out) > 1 {
			actual.Limit = len(out) - 1
		}
		out, window = trimPage(out, actual, func(r Repository) string { return r.Name })
		return nil
	})
	return out, window, e
}
func (s *Store) ArtifactPage(ctx context.Context, i Identity, repo, prefix string, req ListRequest, inventory bool) ([]Artifact, ListWindow, error) {
	out := []Artifact{}
	window := ListWindow{}
	if req.Validate() != nil || len(prefix) > 2048 {
		return out, window, ErrConflict
	}
	compare, order := ">", "ASC"
	if req.Before {
		compare, order = "<", "DESC"
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		columns := artifactColumns
		if req.Summary {
			columns = strings.Replace(columns, "a.metadata", "'{}'::jsonb", 1)
		}
		rows, e := tx.Query(ctx, `SELECT `+columns+` FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository) `+decisionJoin+` WHERE a.repository=$1 AND starts_with(a.path,$2) AND ($3 OR (COALESCE(d.decision,a.decision)<>'denied' AND (NOT r.require_review OR COALESCE(d.decision,a.decision)='allowed'))) AND a.path COLLATE "C" `+compare+` $4 COLLATE "C" AND (a.path||' '||a.digest) COLLATE "C" ~ $5 ORDER BY a.path COLLATE "C" `+order+` LIMIT $6`, repo, prefix, inventory && i.Role == "admin", req.Key, literalSearch(req.Query), req.Limit+1)
		if e != nil {
			return e
		}
		candidates := []Artifact{}
		bytes := 0
		for rows.Next() {
			var a Artifact
			if e = scanArtifact(rows, &a); e != nil {
				rows.Close()
				return e
			}
			if len(a.Metadata) > req.metadataBudget() {
				if len(candidates) == 0 {
					rows.Close()
					return ErrMetadataLimit
				}
				a.Metadata = nil
				candidates = append(candidates, a)
				bytes = req.metadataBudget() + 1
				break
			}
			a.MetadataOmitted = req.Summary
			bytes += len(a.Metadata)
			candidates = append(candidates, a)
			if bytes > req.metadataBudget() && len(candidates) > 1 {
				break
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		actual := req
		if len(candidates) <= req.Limit && bytes > req.metadataBudget() && len(candidates) > 1 {
			actual.Limit = len(candidates) - 1
		}
		// Graph checks use the existing shared reader, within the same current
		// snapshot. Positions of skipped candidates are only exposed as ciphertext.
		count := len(candidates)
		if count > actual.Limit {
			count = actual.Limit
		}
		window.More = len(candidates) > count
		budget := newGraphBudget()
		for n := 0; n < count; n++ {
			a := candidates[n]
			if !inventory || i.Role != "admin" {
				if isManifest(a.MediaType) {
					_, e = readArtifact(ctx, tx, repo, a.Path, r.RequireReview, budget)
					if errors.Is(e, ErrMetadataLimit) && n > 0 {
						window.More = true
						break
					}
					if e != nil && !errors.Is(e, ErrDenied) && !errors.Is(e, ErrNotFound) && !errors.Is(e, ErrOCIUnvalidated) {
						return e
					}
				} else {
					e = nil
				}
			} else {
				e = nil
			}
			if window.First == "" {
				window.First = a.Path
			}
			window.Last = a.Path
			if e == nil {
				out = append(out, a)
			}
		}
		if req.Before {
			slices.Reverse(out)
			window.First, window.Last = window.Last, window.First
		}
		return nil
	})
	return out, window, e
}
func (s *Store) ArtifactReference(ctx context.Context, i Identity, repo, path string, metadataBytes ...int) (Artifact, error) {
	req := ListRequest{Limit: 1}
	if len(metadataBytes) > 0 {
		req.MetadataBytes = metadataBytes[0]
	}
	if req.Validate() != nil {
		return Artifact{}, ErrConflict
	}
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if i.Role != "admin" {
			a, e = readArtifact(ctx, tx, repo, path, r.RequireReview, newGraphBudget())
			return e
		}
		e = scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, path), &a)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	if len(a.Metadata) > req.metadataBudget() {
		return Artifact{}, ErrMetadataLimit
	}
	return a, e
}
