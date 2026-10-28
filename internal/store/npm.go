// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
)

func NPMPath(name, version string) string { return name + "/-/" + name + "-" + version + ".tgz" }
func npmTag(ctx context.Context, tx pgx.Tx, i Identity, repo, name, tag, version string, remove bool, limit int) error {
	if remove {
		result, e := tx.Exec(ctx, `UPDATE cratectl.npm_tags SET deleted=true,revision=revision+1,updated_at=now() WHERE repository=$1 AND package=$2 AND tag=$3`, repo, name, tag)
		if e != nil {
			return e
		}
		if result.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}
	var count int
	var present bool
	if e := tx.QueryRow(ctx, `SELECT count(*),COALESCE(bool_or(tag=$3),false) FROM cratectl.npm_tags WHERE repository=$1 AND package=$2 AND NOT deleted`, repo, name, tag).Scan(&count, &present); e != nil {
		return e
	}
	if count >= limit && !present {
		return ErrMetadataLimit
	}

	var exists bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, repo, NPMPath(name, version)).Scan(&exists); e != nil {
		return e
	}
	if !exists {
		return ErrNotFound
	}
	_, e := tx.Exec(ctx, `INSERT INTO cratectl.npm_tags(tenant,repository,package,tag,version) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,repository,package,tag) DO UPDATE SET version=excluded.version,revision=cratectl.npm_tags.revision+1,deleted=false,updated_at=now()`, i.Tenant, repo, name, tag, version)
	return e
}
func (s *Store) PublishNPM(ctx context.Context, i Identity, repo, name string, artifacts []Artifact, tags map[string]string, limits ...int) error {
	limit := 128
	if len(limits) > 0 {
		limit = limits[0]
	}
	if len(artifacts) != 1 {
		return ErrConflict
	}
	_, e := s.MutateRepository(ctx, i, repo, "", "", "npm.version.published", func(tx pgx.Tx) (any, int, error) {
		if e := InsertArtifacts(ctx, tx, i, repo, artifacts); e != nil {
			return nil, 0, e
		}
		for tag, version := range tags {
			if e := npmTag(ctx, tx, i, repo, name, tag, version, false, limit); e != nil {
				return nil, 0, e
			}
		}
		var stored Artifact
		e := scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, artifacts[0].Path), &stored)
		if e != nil {
			return nil, 0, e
		}
		return map[string]any{"repository": repo, "package": name, "artifact": stored, "dist_tags": tags}, 201, nil
	})
	return e
}
func (s *Store) ChangeNPMTag(ctx context.Context, i Identity, repo, name, tag, version string, remove bool, limits ...int) error {
	limit := 128
	if len(limits) > 0 {
		limit = limits[0]
	}
	_, e := s.MutateRepository(ctx, i, repo, "", "", "npm.tag.changed", func(tx pgx.Tx) (any, int, error) {
		if !remove {
			r, e := repositoryInTx(ctx, tx, i, repo, "write")
			if e != nil {
				return nil, 0, e
			}
			if r.Format != "npm" {
				return nil, 0, ErrConflict
			}
			if _, e = readArtifact(ctx, tx, repo, NPMPath(name, version), false, newGraphBudget()); e != nil {
				return nil, 0, e
			}
		}
		if e := npmTag(ctx, tx, i, repo, name, tag, version, remove, limit); e != nil {
			return nil, 0, e
		}
		return map[string]any{"repository": repo, "package": name, "tag": tag, "version": version, "removed": remove}, 200, nil
	})
	return e
}

var ErrMetadataLimit = errors.New("native metadata exceeds the configured safety budget")

// NPMState returns one authorization/policy snapshot. Budgets reject an oversized
// index explicitly; silently truncating an index would change dependency resolution.
func (s *Store) NPMState(ctx context.Context, i Identity, repo, name string, maxVersions int, maxBytes int64, tagLimits ...int) ([]Artifact, map[string]string, error) {
	tagLimit := 128
	if len(tagLimits) > 0 {
		tagLimit = tagLimits[0]
	}
	out := []Artifact{}
	tags := map[string]string{}
	if maxVersions <= 0 || maxBytes <= 0 {
		return nil, nil, ErrMetadataLimit
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		var count int
		var bytes int64
		if e = tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(metadata::text)),0) FROM (SELECT metadata FROM cratectl.artifacts WHERE repository=$1 AND starts_with(path,$2) ORDER BY path LIMIT $3) bounded`, repo, name+"/-/", maxVersions+1).Scan(&count, &bytes); e != nil {
			return e
		}
		if count > maxVersions || bytes > maxBytes {
			return ErrMetadataLimit
		}
		rows, e := tx.Query(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND starts_with(a.path,$2) ORDER BY a.path LIMIT $3`, repo, name+"/-/", maxVersions+1)
		if e != nil {
			return e
		}
		visibleVersions := map[string]bool{}
		for rows.Next() {
			var a Artifact
			if e = scanArtifact(rows, &a); e != nil {
				rows.Close()
				return e
			}
			if a.Decision == "denied" || (r.RequireReview && a.Decision != "allowed") {
				continue
			}
			out = append(out, a)
			var metadata struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(a.Metadata, &metadata) == nil {
				visibleVersions[metadata.Version] = true
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		tagRows, e := tx.Query(ctx, `SELECT tag,version FROM cratectl.npm_tags WHERE repository=$1 AND package=$2 AND NOT deleted ORDER BY tag LIMIT $3`, repo, name, tagLimit+1)
		if e != nil {
			return e
		}
		defer tagRows.Close()
		n := 0
		for tagRows.Next() {
			n++
			if n > tagLimit {
				return ErrMetadataLimit
			}
			var tag, version string
			if e = tagRows.Scan(&tag, &version); e != nil {
				return e
			}
			if visibleVersions[version] {
				tags[tag] = version
			}
		}
		return tagRows.Err()
	})
	return out, tags, e
}
