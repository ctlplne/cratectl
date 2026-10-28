// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrOCIUnvalidated = errors.New("OCI manifest structure has not been validated")

type OCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}
type OCIManifestMetadata struct {
	Validated    bool                     `json:"oci_validated"`
	References   []string                 `json:"oci_references"`
	Descriptors  map[string]OCIDescriptor `json:"oci_descriptors"`
	Subject      *OCIDescriptor           `json:"oci_subject,omitempty"`
	ArtifactType string                   `json:"oci_artifact_type,omitempty"`
	Annotations  map[string]string        `json:"oci_annotations,omitempty"`
}
type OCIReferrer struct {
	OCIDescriptor
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func (s *Store) OCIManifest(ctx context.Context, i Identity, repo, image, ref string) (Artifact, error) {
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" || r.Mode != "hosted" {
			return ErrConflict
		}
		digest := ref
		if !strings.HasPrefix(ref, "sha256:") {
			if e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3`, repo, image, ref).Scan(&digest); errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			} else if e != nil {
				return e
			}
		}
		a, e = readArtifact(ctx, tx, repo, image+"/manifests/"+digest, r.RequireReview, newGraphBudget())
		return e
	})
	return a, e
}

func checkOCISubject(ctx context.Context, tx pgx.Tx, repo, image string, d OCIDescriptor, review bool, budget *graphBudget) error {
	p := image + "/manifests/" + d.Digest
	var exists bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, repo, p).Scan(&exists); e != nil {
		return e
	}
	if !exists {
		return nil
	}
	a, e := readArtifact(ctx, tx, repo, p, review, budget)
	if e != nil {
		return e
	}
	if a.Size != d.Size || a.MediaType != d.MediaType || "sha256:"+a.Digest != d.Digest {
		return ErrConflict
	}
	return nil
}

// PublishOCI rechecks the complete durable graph inside the publication
// transaction. A policy update cannot slip between a preflight read and tag
// publication. The subject is a weak association: it may arrive later. When it
// exists its identity and current policy still apply to this intake.
func PublishOCI(ctx context.Context, tx pgx.Tx, i Identity, repo, image, tag string, a Artifact, metadata OCIManifestMetadata) error {
	r, e := repositoryInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return e
	}
	if r.Mode != "hosted" || r.Format != "oci" || !metadata.Validated || len(metadata.References) > 4096 || len(metadata.Descriptors) > 4096 {
		return ErrConflict
	}
	for _, p := range metadata.References {
		d, ok := metadata.Descriptors[p]
		if !ok || (!strings.HasPrefix(p, image+"/blobs/") && !strings.HasPrefix(p, image+"/manifests/")) || !strings.HasSuffix(p, "/"+d.Digest) {
			return ErrConflict
		}
		child, e := readArtifact(ctx, tx, repo, p, false, newGraphBudget())
		if e != nil {
			return e
		}
		if "sha256:"+child.Digest != d.Digest || child.Size != d.Size || (strings.HasPrefix(p, image+"/manifests/") && child.MediaType != d.MediaType) {
			return ErrConflict
		}
	}
	if d := metadata.Subject; d != nil {
		if e = checkOCISubject(ctx, tx, repo, image, *d, false, newGraphBudget()); e != nil {
			return e
		}
	}
	if !isManifest(a.MediaType) || a.Path != image+"/manifests/sha256:"+a.Digest {
		return ErrConflict
	}
	var priorMedia string
	var priorSize int64
	e = tx.QueryRow(ctx, `SELECT media_type,size FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, a.Path).Scan(&priorMedia, &priorSize)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if e == nil && (priorMedia != a.MediaType || priorSize != a.Size) {
		return ErrConflict
	}
	a.Metadata, e = json.Marshal(metadata)
	if e != nil {
		return e
	}
	if e = InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); e != nil {
		return e
	}
	// Same-byte authorized re-import enriches pre-parser development records.
	// Canonical digest decisions and the original bytes remain unchanged.
	_, e = tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=$1 WHERE repository=$2 AND path=$3 AND digest=$4`, a.Metadata, repo, a.Path, a.Digest)
	if e != nil {
		return e
	}
	if _, e = readArtifact(ctx, tx, repo, a.Path, false, newGraphBudget()); e != nil {
		return e
	}
	if tag != "" {
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.tags(tenant,repository,image,tag,digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,repository,image,tag) DO UPDATE SET digest=excluded.digest,version=cratectl.tags.version+1`, i.Tenant, repo, image, tag, "sha256:"+a.Digest)
	}
	return e
}

// OCIReferrers returns a complete bounded index from one authorization/policy
// snapshot. Querying a denied subject or a denied referrer cannot disclose its
// graph. Missing subjects are allowed by OCI's weak association semantics.
func (s *Store) OCIReferrers(ctx context.Context, i Identity, repo, image, subject, artifactType string, limit int, byteLimit int64) ([]OCIReferrer, error) {
	out := []OCIReferrer{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "oci" || r.Mode != "hosted" || limit <= 0 || byteLimit <= 0 {
			return ErrConflict
		}
		if _, e = readArtifact(ctx, tx, repo, image+"/manifests/"+subject, r.RequireReview, newGraphBudget()); e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT path,octet_length(metadata::text) FROM cratectl.artifacts WHERE repository=$1 AND starts_with(path,$2) AND metadata->'oci_subject'->>'digest'=$3 ORDER BY path LIMIT $4`, repo, image+"/manifests/", subject, limit+1)
		if e != nil {
			return e
		}
		paths := []string{}
		var budget int64
		for rows.Next() {
			var p string
			var size int64
			if e = rows.Scan(&p, &size); e != nil {
				rows.Close()
				return e
			}
			budget += size
			if budget > byteLimit || len(paths) >= limit {
				rows.Close()
				return ErrMetadataLimit
			}
			paths = append(paths, p)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, p := range paths {
			a, e := readArtifact(ctx, tx, repo, p, r.RequireReview, newGraphBudget())
			if errors.Is(e, ErrDenied) || errors.Is(e, ErrNotFound) {
				continue
			}
			if e != nil {
				return e
			}
			var metadata OCIManifestMetadata
			if json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated {
				return ErrConflict
			}
			if artifactType == "" || metadata.ArtifactType == artifactType {
				out = append(out, OCIReferrer{OCIDescriptor{a.MediaType, "sha256:" + a.Digest, a.Size}, metadata.ArtifactType, metadata.Annotations})
			}
		}
		return nil
	})
	return out, e
}
