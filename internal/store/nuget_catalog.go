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

var ErrNuGetCatalogRequired = errors.New("NuGet discovery catalog requires an administrator rebuild")

func (s *Store) NuGetRegistrationVersion(ctx context.Context, i Identity, repo, id, version string, budget int64) (Artifact, error) {
	var a Artifact
	if k, e := nuget.IDKey(id); e != nil || k != id {
		return a, ErrNotFound
	}
	if k, e := nuget.VersionKey(version); e != nil || k != version {
		return a, ErrNotFound
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return ErrConflict
		}
		path := NuGetPath(id, version)
		var n int64
		e = tx.QueryRow(ctx, `SELECT octet_length(metadata::text) FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, path).Scan(&n)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if n > budget || n > MaxNuGetMetadataBytes {
			return ErrMetadataLimit
		}
		a, e = readArtifact(ctx, tx, repo, path, r.RequireReview, repositoryReadBudget(r))
		if e != nil {
			return e
		}
		_, e = ValidateNuGetArtifact(ctx, a)
		return e
	})
	return a, e
}

const nugetVisible = ` a.repository=$1 AND a.metadata->>'id_profile'=$2 AND a.metadata->>'archive_validated'='true' AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $3::boolean OR COALESCE(d.decision,a.decision)='allowed') `

// NuGetRegistration bounds both the key inventory and total SQL-returned metadata
// before loading any manifests. Unlisted versions remain available to pinned clients.
func (s *Store) NuGetRegistration(ctx context.Context, i Identity, repo, id string, limit int, budget int64) ([]Artifact, error) {
	if key, e := nuget.IDKey(id); e != nil || key != id || limit < 1 || limit > nuget.MaxOrderedVersions || budget < 1 {
		return nil, ErrMetadataLimit
	}
	out := []Artifact{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, e := tx.Query(ctx, `SELECT left(a.path,2049),octet_length(a.metadata::text) FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+` WHERE `+nugetVisible+` AND a.metadata->>'id_key'=$4 ORDER BY a.path COLLATE "C" LIMIT $5`, repo, nuget.IDKeyProfile, r.RequireReview, id, limit+1)
		if e != nil {
			return e
		}
		paths := []string{}
		for rows.Next() {
			var path string
			var size int64
			if e = rows.Scan(&path, &size); e != nil {
				break
			}
			budget -= size + int64(len(path)+256)
			if len(paths) >= limit || len(path) > 2048 || size > MaxNuGetMetadataBytes || budget < 0 {
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
			return e
		}
		for _, path := range paths {
			var a Artifact
			if e = scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, path), &a); e != nil {
				return e
			}
			if _, e = ValidateNuGetArtifact(ctx, a); e != nil {
				return e
			}
			out = append(out, a)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}

type NuGetSearchRequest struct {
	Query               string
	Skip, Take          int
	Prerelease, SemVer2 bool
}

func (q NuGetSearchRequest) Valid() bool {
	return len(q.Query) <= 256 && utf8.ValidString(q.Query) && !strings.ContainsRune(q.Query, 0) && q.Skip >= 0 && q.Skip <= 100000 && q.Take >= 1 && q.Take <= 1000
}

type NuGetSearchItem struct {
	IDKey    string
	Catalog  nuget.Catalog
	Versions []string
}

// NuGetSearch uses only compact derived catalogs. Current permission, policy,
// retirement and listing filters are evaluated in one repeatable-read snapshot.
// Missing old projections fail explicitly instead of disappearing from results.
func (s *Store) NuGetSearch(ctx context.Context, i Identity, repo string, q NuGetSearchRequest, versionLimit int, budget int64) ([]NuGetSearchItem, int64, error) {
	if !q.Valid() || versionLimit < 1 || versionLimit > nuget.MaxOrderedVersions || budget < 1 {
		return nil, 0, ErrMetadataLimit
	}
	out := []NuGetSearchItem{}
	var total int64
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return ErrConflict
		}
		var missing bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+` WHERE `+nugetVisible+` AND (a.metadata->'catalog'->>'profile' IS DISTINCT FROM $4 OR a.metadata->'catalog'->>'source_sha256' IS DISTINCT FROM a.metadata->>'nuspec_sha256'))`, repo, nuget.IDKeyProfile, r.RequireReview, nuget.CatalogProfile).Scan(&missing); e != nil {
			return e
		}
		if missing {
			return ErrNuGetCatalogRequired
		}
		// Parameters 1..6 are identical in the count, page and version queries.
		eligible := ` FROM cratectl.artifacts a ` + decisionJoin + nativeLifecycleJoin + ` WHERE ` + nugetVisible + ` AND COALESCE(a.metadata->>'listed','true')='true' AND ($4::boolean OR a.metadata->'catalog'->>'prerelease'='false') AND ($5::boolean OR a.metadata->'catalog'->>'semver2'='false') `
		latest := `WITH latest AS (SELECT DISTINCT ON ((a.metadata->>'id_key') COLLATE "C") a.path,a.metadata->>'id_key' AS id,a.metadata->'catalog' AS c ` + eligible + ` ORDER BY (a.metadata->>'id_key') COLLATE "C",(a.metadata->'catalog'->>'order') COLLATE "C" DESC,a.path COLLATE "C") `
		match := `position(lower($6::text) in lower(concat_ws(' ',c->'values'->>'id',c->'values'->>'title',c->'values'->>'description',c->'values'->>'tags')))>0`
		args := []any{repo, nuget.IDKeyProfile, r.RequireReview, q.Prerelease, q.SemVer2, q.Query}
		if e = tx.QueryRow(ctx, latest+`SELECT count(*) FROM latest WHERE `+match, args...).Scan(&total); e != nil {
			return e
		}
		pageArgs := append(append([]any{}, args...), q.Take, q.Skip)
		rows, e := tx.Query(ctx, latest+`SELECT left(id,401),left(path,2049),octet_length(c::text) FROM latest WHERE `+match+` ORDER BY id COLLATE "C" LIMIT $7 OFFSET $8`, pageArgs...)
		if e != nil {
			return e
		}
		type entry struct{ id, path string }
		entries := []entry{}
		for rows.Next() {
			var x entry
			var n int64
			if e = rows.Scan(&x.id, &x.path, &n); e != nil {
				break
			}
			budget -= n + int64(len(x.id)+len(x.path)+128)
			if n > MaxNuGetMetadataBytes || budget < 0 || len(x.path) > 2048 || len(x.id) > 400 {
				e = ErrMetadataLimit
				break
			}
			entries = append(entries, x)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return e
		}
		for _, x := range entries {
			var raw []byte
			var source, key string
			if e = tx.QueryRow(ctx, `SELECT metadata->'catalog',left(metadata->>'nuspec_sha256',65),left(metadata->>'version_key',1025) FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, x.path).Scan(&raw, &source, &key); e != nil {
				return e
			}
			item := NuGetSearchItem{IDKey: x.id, Versions: []string{}}
			if json.Unmarshal(raw, &item.Catalog) != nil || item.Catalog.Profile != nuget.CatalogProfile || item.Catalog.SourceSHA != source {
				return ErrNuGetCatalogRequired
			}
			id, err := nuget.IDKey(item.Catalog.Values["id"])
			order, orderErr := nuget.VersionOrderKey(key)
			version, versionErr := nuget.VersionKey(item.Catalog.Version)
			if err != nil || id != x.id || orderErr != nil || order != item.Catalog.Order || versionErr != nil || version != key || x.path != NuGetPath(x.id, key) {
				return ErrNuGetCatalogRequired
			}
			versionArgs := append(append([]any{}, args[:5]...), x.id, versionLimit+1)
			vr, err := tx.Query(ctx, `SELECT left(a.metadata->'catalog'->>'version',2049) `+eligible+` AND a.metadata->>'id_key'=$6 ORDER BY (a.metadata->'catalog'->>'order') COLLATE "C",a.path COLLATE "C" LIMIT $7`, versionArgs...)
			if err != nil {
				return err
			}
			for vr.Next() {
				var v string
				if e = vr.Scan(&v); e != nil {
					break
				}
				budget -= int64(len(v) + 128)
				if len(item.Versions) >= versionLimit || budget < 0 {
					e = ErrMetadataLimit
					break
				}
				if _, err = nuget.VersionKey(v); err != nil {
					e = ErrNuGetCatalogRequired
					break
				}
				item.Versions = append(item.Versions, v)
			}
			if e == nil {
				e = vr.Err()
			}
			vr.Close()
			if e != nil {
				return e
			}
			out = append(out, item)
		}
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	return out, total, nil
}
