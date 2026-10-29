// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// CheckOCIDigestDecision rejects a current byte-level denial before a direct
// digest request enters cache or source retrieval. It does not admit a graph.
func (s *Store) CheckOCIDigestDecision(ctx context.Context, i Identity, repo, digest string) error {
	return s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" {
			return ErrConflict
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
func (s *Store) OCIReferenceParents(ctx context.Context, i Identity, repo, image, kind, digest string, limit int, byteLimit int64) ([]Artifact, error) {
	out := []Artifact{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" || r.Mode != "proxy" || (kind != "blobs" && kind != "manifests") || !strings.HasPrefix(digest, "sha256:") || limit < 1 || limit > 4096 || byteLimit < 1 {
			return ErrConflict
		}
		var denied bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.content_decisions WHERE repository=$1 AND digest=$2 AND decision='denied')`, repo, strings.TrimPrefix(digest, "sha256:")).Scan(&denied); e != nil {
			return e
		}
		if denied {
			return ErrDenied
		}
		rows, e := tx.Query(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2 || '/manifests/sha256:' || a.digest AND a.metadata->>'oci_validated'='true' AND COALESCE(d.decision,a.decision)<>'denied' AND ((a.metadata->'oci_descriptors') ? $3 OR ($4='manifests' AND (a.metadata->'oci_subject')->>'digest'=$5)) ORDER BY a.path LIMIT $6`, repo, image, image+"/"+kind+"/"+digest, kind, digest, limit+1)
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
