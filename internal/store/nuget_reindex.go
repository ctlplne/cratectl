// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/nuget"
	"github.com/jackc/pgx/v5"
)

type NuGetReindexRequest struct {
	After  string `json:"after_path"`
	Limit  int    `json:"limit"`
	DryRun bool   `json:"dry_run"`
	Reason string `json:"reason"`
}

type NuGetReindexResult struct {
	Repository    string `json:"repository"`
	After         string `json:"after_path"`
	More          bool   `json:"more"`
	Examined      int    `json:"examined"`
	Changed       int    `json:"changed"`
	DryRun        bool   `json:"dry_run"`
	RetainedBytes bool   `json:"retained_bytes"`
	Reason        string `json:"reason"`
}

// RebuildNuGetCatalog changes only derived metadata. Each bounded batch, event,
// outbox intent and retry receipt commits under the common tenant mutation fence.
// The caller can cancel between batches; a failed batch has no partial changes.
func (s *Store) RebuildNuGetCatalog(ctx context.Context, i Identity, repo, key, fingerprint string, input NuGetReindexRequest, budget int64) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if input.Limit < 1 || input.Limit > 1000 || len(input.After) > 2048 || !utf8.ValidString(input.After) || strings.ContainsRune(input.After, 0) || !validLifecycleReason(input.Reason) || strings.TrimSpace(input.Reason) == "" || budget < 1 {
		return Result{}, ErrConfigurationInput
	}
	fn := func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		out := NuGetReindexResult{Repository: repo, After: input.After, DryRun: input.DryRun, RetainedBytes: true, Reason: input.Reason}
		rows, e := tx.Query(ctx, `SELECT left(path,2049),octet_length(metadata::text) FROM cratectl.artifacts WHERE repository=$1 AND starts_with(path,'nuget-packages/') AND path COLLATE "C">$2 COLLATE "C" ORDER BY path COLLATE "C" LIMIT $3`, repo, input.After, input.Limit+1)
		if e != nil {
			return nil, 0, e
		}
		paths := []string{}
		for rows.Next() {
			var path string
			var n int64
			if e = rows.Scan(&path, &n); e != nil {
				break
			}
			if len(paths) == input.Limit {
				out.More = true
				break
			}
			budget -= n + int64(len(path)+256)
			if budget < 0 || n > MaxNuGetMetadataBytes || len(path) > 2048 {
				e = ErrMetadataLimit
				break
			}
			paths = append(paths, path)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return nil, 0, e
		}
		for _, path := range paths {
			var a Artifact
			if e = scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, path), &a); e != nil {
				return nil, 0, e
			}
			m, e := ValidateNuGetArtifact(ctx, a)
			if e != nil {
				return nil, 0, e
			}
			c, e := nuget.BuildCatalog(ctx, m.Nuspec)
			if e != nil {
				return nil, 0, errors.Join(ErrNuGetUnvalidated, e)
			}
			c.SourceSHA = m.NuspecSHA256
			data, e := json.Marshal(c)
			if e != nil {
				return nil, 0, e
			}
			var changed bool
			var projectedBytes int64
			if e = tx.QueryRow(ctx, `SELECT metadata->'catalog' IS DISTINCT FROM $3::jsonb,octet_length(jsonb_set(metadata,'{catalog}',$3::jsonb,true)::text) FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, path, data).Scan(&changed, &projectedBytes); e != nil {
				return nil, 0, e
			}
			if projectedBytes > MaxNuGetMetadataBytes {
				return nil, 0, ErrMetadataLimit
			}
			if changed {
				out.Changed++
				if !input.DryRun {
					if _, e = tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{catalog}',$3::jsonb,true) WHERE repository=$1 AND path=$2`, repo, path, data); e != nil {
						return nil, 0, e
					}
				}
			}
			out.Examined++
			out.After = path
		}
		return out, 200, nil
	}
	if input.DryRun {
		var result Result
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			body, status, e := fn(tx)
			if e != nil {
				return e
			}
			result.Body, e = json.Marshal(body)
			result.Status = status
			return e
		})
		return result, e
	}
	if key == "" {
		return Result{}, ErrConfigurationInput
	}
	return s.MutateRepository(ctx, i, repo, key, fingerprint, "nuget.catalog.rebuilt", fn)
}
