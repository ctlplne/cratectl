// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"github.com/jackc/pgx/v5"
)

var ErrNuGetUnvalidated = errors.New("NuGet archive identity is missing or inconsistent")

// NuGetPackage binds the original manifest bytes to one immutable parent nupkg.
// Validated denotes bounded archive inspection, not signature or scan approval.
type NuGetPackage struct {
	ID           string `json:"id"`
	IDKey        string `json:"id_key"`
	IDProfile    string `json:"id_profile"`
	RawVersion   string `json:"raw_version"`
	VersionKey   string `json:"version_key"`
	NuspecPath   string `json:"nuspec_path"`
	Nuspec       []byte `json:"nuspec"`
	NuspecSHA256 string `json:"nuspec_sha256"`
	Validated    bool   `json:"archive_validated"`
}

func NuGetPath(id, version string) string {
	return "nuget-packages/" + id + "/" + version + ".nupkg"
}

// ValidateNuGetArtifact fails closed for development or inconsistent records.
// It does not replace the intake caller's inspection of the durable parent.
func ValidateNuGetArtifact(ctx context.Context, a Artifact) (NuGetPackage, error) {
	var m NuGetPackage
	if len(a.Metadata) > 2*nuget.MaxNuspecBytes+8192 || json.Unmarshal(a.Metadata, &m) != nil || !m.Validated || m.IDProfile != nuget.IDKeyProfile || len(m.Nuspec) == 0 || len(m.Nuspec) > nuget.MaxNuspecBytes {
		return m, ErrNuGetUnvalidated
	}
	id, e := nuget.IDKey(m.ID)
	if e != nil || id != m.IDKey || a.Path != NuGetPath(id, m.VersionKey) || a.Size <= 0 || a.MediaType != "application/octet-stream" {
		return m, ErrNuGetUnvalidated
	}
	digest, e := hex.DecodeString(a.Digest)
	if e != nil || len(digest) != 32 || a.Digest != strings.ToLower(a.Digest) || crypt.Digest(m.Nuspec) != m.NuspecSHA256 || strings.ContainsAny(m.NuspecPath, "/\\") || !strings.HasSuffix(strings.ToLower(m.NuspecPath), ".nuspec") {
		return m, ErrNuGetUnvalidated
	}
	identity, e := nuget.ParseNuspecIdentity(ctx, m.Nuspec)
	if e != nil || identity.ID != m.ID || identity.RawVersion != m.RawVersion || identity.VersionKey != m.VersionKey {
		return m, ErrNuGetUnvalidated
	}
	return m, nil
}

func (s *Store) PublishNuGet(ctx context.Context, i Identity, repo string, a Artifact) error {
	if _, e := ValidateNuGetArtifact(ctx, a); e != nil {
		return e
	}
	_, e := s.MutateRepository(ctx, i, repo, "", "", "nuget.package.published", func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		if e = notDeletedInTx(ctx, tx, repo, a.Path); e != nil {
			return nil, 0, e
		}
		// The common tenant mutation fence serializes coordinate publication.
		// Even a byte-identical duplicate is a native 409 (skip-duplicate works).
		var exists bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, repo, a.Path).Scan(&exists); e != nil {
			return nil, 0, e
		}
		if exists {
			return nil, 0, ErrConflict
		}
		if e = InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); e != nil {
			return nil, 0, e
		}
		// Avoid duplicating the entire manifest in the publication event.
		return map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size}, 201, nil
	})
	return e
}

// NuGetVersions projects only bounded keys. It never loads all package manifests
// to construct an index, and filters current policy and retirement in one snapshot.
func (s *Store) NuGetVersions(ctx context.Context, i Identity, repo, id string, limit int, maxBytes int64) ([]string, error) {
	versions := []string{}
	key, e := nuget.IDKey(id)
	if e != nil || key != id || limit <= 0 || limit > 100000 || maxBytes <= 0 {
		return nil, ErrMetadataLimit
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "nuget" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, e := tx.Query(ctx, `SELECT left(a.metadata->>'version_key',1025),left(a.path,2049) FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+` WHERE a.repository=$1 AND a.metadata->>'id_key'=$2 AND a.metadata->>'id_profile'=$3 AND a.metadata->>'archive_validated'='true' AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed') ORDER BY a.path LIMIT $5`, repo, id, nuget.IDKeyProfile, r.RequireReview, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var version, path string
			if e = rows.Scan(&version, &path); e != nil {
				return e
			}
			normal, e := nuget.VersionKey(version)
			if e != nil || normal != version || path != NuGetPath(id, version) {
				return ErrNuGetUnvalidated
			}
			maxBytes -= int64(len(version) + 4)
			if len(versions) >= limit || maxBytes < 0 {
				return ErrMetadataLimit
			}
			versions = append(versions, version)
		}
		return rows.Err()
	})
	return versions, e
}
