// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ociReferenceLifecycleInTx(ctx context.Context, tx pgx.Tx, repo Repository, image, kind, ref string) error {
	digest := ref
	if kind == "manifests" && !strings.HasPrefix(ref, "sha256:") {
		var deleted bool
		var revision int64
		e := tx.QueryRow(ctx, `SELECT digest,deleted,source_revision FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3`, repo.Name, image, ref).Scan(&digest, &deleted, &revision)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if deleted && repo.Mode == "hosted" {
			return ErrDeleted
		}
		if repo.Mode == "proxy" && (deleted || revision != repo.SourceRevision) {
			return nil
		}
	}
	return notDeletedInTx(ctx, tx, repo.Name, image+"/"+kind+"/"+digest)
}

// A known deleted tag target stays authoritative even when cache validation has
// expired or a forced upstream request could otherwise turn it into a miss.
func (s *Store) CheckOCIReferenceLifecycle(ctx context.Context, i Identity, repo, image, kind, ref string) error {
	return s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" {
			return ErrConflict
		}
		return ociReferenceLifecycleInTx(ctx, tx, r, image, kind, ref)
	})
}

// CheckOCIDigestDecision rejects a current byte-level denial before a direct
// digest request enters cache or source retrieval. It does not admit a graph.
func (s *Store) CheckOCIDigestDecision(ctx context.Context, i Identity, repo, digest string, paths ...string) error {
	return s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" {
			return ErrConflict
		}
		for _, path := range paths {
			if !lifecycleOCIPath(path) || !strings.HasSuffix(path, digest) {
				return ErrConflict
			}
			if e = notDeletedInTx(ctx, tx, repo, path); e != nil {
				return e
			}
		}
		var denied bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.content_decisions WHERE repository=$1 AND digest=$2 AND decision='denied')`, repo, strings.TrimPrefix(digest, "sha256:")).Scan(&denied); e != nil {
			return e
		}
		if denied {
			return ErrDenied
		}
		return nil
	})
}

// OCIReferenceParents returns bounded, canonical intake metadata. It is not a
// serving authorization. Callers must verify/reparse the exact immutable bytes;
// publication and every served read independently recheck current graph policy.
func (s *Store) OCIReferenceParents(ctx context.Context, i Identity, repo, image, kind, digest string, limit int, byteLimit int64, expected ...int64) ([]Artifact, error) {
	out := []Artifact{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" || r.Mode != "proxy" || (kind != "blobs" && kind != "manifests") || !strings.HasPrefix(digest, "sha256:") || limit < 1 || limit > 4096 || byteLimit < 1 {
			return ErrConflict
		}
		if len(expected) > 0 && r.SourceRevision != expected[0] {
			return ErrSourceChanged
		}
		var denied bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.content_decisions WHERE repository=$1 AND digest=$2 AND decision='denied')`, repo, strings.TrimPrefix(digest, "sha256:")).Scan(&denied); e != nil {
			return e
		}
		if denied {
			return ErrDenied
		}
		if e = notDeletedInTx(ctx, tx, repo, image+"/"+kind+"/"+digest); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.source_revision=$7 AND a.path=$2 || '/manifests/sha256:' || a.digest AND a.metadata->>'oci_validated'='true' AND COALESCE(d.decision,a.decision)<>'denied' AND NOT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle l WHERE (l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path) AND l.deleted) AND ((a.metadata->'oci_descriptors') ? $3 OR ($4='manifests' AND (a.metadata->'oci_subject')->>'digest'=$5)) ORDER BY a.path LIMIT $6`, repo, image, image+"/"+kind+"/"+digest, kind, digest, limit+1, r.SourceRevision)
		if e != nil {
			return e
		}
		defer rows.Close()
		var used int64
		for rows.Next() {
			var a Artifact
			if e = scanArtifact(rows, &a); e != nil {
				return e
			}
			if !isManifest(a.MediaType) || len(out) >= limit || a.Size < 0 || a.Size > byteLimit-used {
				return ErrMetadataLimit
			}
			used += a.Size
			if int64(len(a.Metadata)) > byteLimit-used {
				return ErrMetadataLimit
			}
			used += int64(len(a.Metadata))
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, e
}
