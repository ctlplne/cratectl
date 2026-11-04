// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

func isManifest(media string) bool {
	switch media {
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json":
		return true
	}
	return false
}

type graphBudget struct {
	retainedRoot    string
	retained        bool
	observation     bool
	sourceRevision  *int64
	remaining       int
	depth           int
	stack           map[string]bool
	checked         map[string]Artifact
	metadataBytes   int64
	cacheRepository string
	admissions      []OCIAdmission
}

func newGraphBudget() *graphBudget {
	return &graphBudget{remaining: 4096, metadataBytes: 32 << 20, stack: map[string]bool{}, checked: map[string]Artifact{}}
}

// readArtifact evaluates all members of an OCI graph from one PostgreSQL read
// snapshot. A result only admits this request. Missing graph metadata fails
// closed, including pre-graph development records that need re-import/repair.
func readArtifact(ctx context.Context, tx pgx.Tx, repo, path string, review bool, b *graphBudget) (Artifact, error) {
	if b.stack[path] {
		return Artifact{}, ErrDenied
	}
	if a, ok := b.checked[path]; ok {
		return a, nil
	}
	if b.depth >= 32 || b.remaining <= 0 {
		return Artifact{}, ErrMetadataLimit
	}
	b.remaining--
	b.depth++
	b.stack[path] = true
	defer func() { b.depth--; delete(b.stack, path) }()
	var a Artifact
	e := scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, path), &a)
	if errors.Is(e, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if e != nil {
		return a, e
	}
	if !b.observation && path != b.retainedRoot {
		if e = notDeletedInTx(ctx, tx, repo, path); e != nil {
			return a, e
		}
	}
	if b.sourceRevision != nil && a.SourceRevision != *b.sourceRevision {
		return a, ErrSourceChanged
	}
	b.metadataBytes -= int64(len(a.Metadata))
	if b.metadataBytes < 0 {
		return a, ErrMetadataLimit
	}
	if !b.retained && (a.Decision == "denied" || (review && a.Decision != "allowed")) {
		return a, ErrDenied
	}
	if b.cacheRepository != "" {
		var exists bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.retrievals WHERE repository=$1 AND path=$2)`, repo, path).Scan(&exists); e != nil {
			return a, e
		}
		if !exists {
			return a, ErrOCICacheExpired
		}
		valid, e := ociCacheInTx(ctx, tx, repo, path, b.admissions...)
		if e != nil {
			return a, e
		}
		if !valid {
			return a, ErrDenied
		}
	}
	if isManifest(a.MediaType) {
		var metadata struct {
			References  *[]string                `json:"oci_references"`
			Validated   bool                     `json:"oci_validated"`
			Descriptors map[string]OCIDescriptor `json:"oci_descriptors"`
			Subject     *OCIDescriptor           `json:"oci_subject"`
		}
		if json.Unmarshal(a.Metadata, &metadata) != nil || metadata.References == nil || len(*metadata.References) > 4096 {
			return a, ErrDenied
		}
		if !metadata.Validated {
			return a, ErrOCIUnvalidated
		}
		for _, ref := range *metadata.References {
			if len(ref) > 2048 || !strings.Contains(ref, "/") {
				return a, ErrDenied
			}
			child, e := readArtifact(ctx, tx, repo, ref, review, b)
			if e != nil {
				return a, e
			}
			if metadata.Validated {
				d, ok := metadata.Descriptors[ref]
				if !ok || "sha256:"+child.Digest != d.Digest || child.Size != d.Size || (isManifest(child.MediaType) && child.MediaType != d.MediaType) {
					return a, ErrDenied
				}
			}
		}
		if metadata.Subject != nil {
			separator := strings.LastIndex(path, "/manifests/")
			if separator <= 0 {
				return a, ErrDenied
			}
			image := path[:separator]
			if e = checkOCISubject(ctx, tx, repo, image, *metadata.Subject, review, b); e != nil {
				return a, e
			}
		}
	}
	b.checked[path] = a
	return a, nil
}
func (s *Store) artifact(ctx context.Context, i Identity, repo, path string, intake bool, snapshots ...SourceSnapshot) (Artifact, error) {
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		review := r.RequireReview
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if len(snapshots) > 0 {
			review, e = checkSourceSnapshot(ctx, tx, i, r, snapshots[0])
			if e != nil {
				return e
			}
		}
		a, e = readArtifact(ctx, tx, repo, path, review && !intake, repositoryReadBudget(r))
		if r.Format == "go" && errors.Is(e, ErrNotFound) {
			e = missingGoModuleRepresentation(ctx, tx, repo, path)
		}
		if e == nil && r.Format == "pypi" && a.MediaType != PythonCatalogMedia {
			var metadata PythonFile
			if json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated {
				return ErrPythonUnvalidated
			}
		}
		if e == nil && r.Format == "go" {
			e = checkGoModuleBundle(ctx, tx, repo, a, review && !intake, repositoryReadBudget(r))
		}
		if e == nil && r.Format == "nuget" {
			if _, e = ValidateNuGetArtifact(ctx, a); e != nil {
				return e
			}
		}
		if e == nil && len(snapshots) > 0 {
			e = checkNativeRetirementPrecedence(ctx, tx, i, r, a, snapshots[0].Groups)
		}
		return e
	})
	return a, e
}
func (s *Store) Artifact(ctx context.Context, i Identity, repo, path string) (Artifact, error) {
	return s.artifact(ctx, i, repo, path, false)
}

func (s *Store) ArtifactSelection(ctx context.Context, i Identity, repo, path string, snapshot SourceSnapshot) (Artifact, error) {
	return s.artifact(ctx, i, repo, path, false, snapshot)
}

// ArtifactForPublication checks durable references for an authorized publisher.
// Unassessed children can form a quarantined graph. Denied children cannot.
// This method never serves their contents to the publisher.
func (s *Store) ArtifactForPublication(ctx context.Context, i Identity, repo, path string) (Artifact, error) {
	if !i.CanWrite() {
		return Artifact{}, ErrDenied
	}
	return s.artifact(ctx, i, repo, path, true)
}
func (s *Store) Tags(ctx context.Context, i Identity, repo, image string) ([]string, error) {
	out := []string{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		review := r.RequireReview
		rows, e := tx.Query(ctx, `SELECT tag,digest FROM cratectl.tags WHERE repository=$1 AND image=$2 AND NOT deleted ORDER BY tag LIMIT 1000`, repo, image)
		if e != nil {
			return e
		}
		type pair struct{ tag, digest string }
		pairs := []pair{}
		for rows.Next() {
			var p pair
			if e = rows.Scan(&p.tag, &p.digest); e != nil {
				rows.Close()
				return e
			}
			pairs = append(pairs, p)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, p := range pairs {
			_, e = readArtifact(ctx, tx, repo, image+"/manifests/"+p.digest, review, newGraphBudget())
			if errors.Is(e, ErrDenied) || errors.Is(e, ErrNotFound) || errors.Is(e, ErrDeleted) {
				continue
			}
			if e != nil {
				return e
			}
			out = append(out, p.tag)
		}
		return nil
	})
	return out, e
}
