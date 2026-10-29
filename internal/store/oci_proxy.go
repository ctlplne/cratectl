// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

const OCICatalogMedia = "application/vnd.cratectl.oci.catalog.v1+json"

var ErrOCICache = errors.New("OCI source cache is unavailable")

type OCICatalog struct {
	Image     string            `json:"image"`
	Tags      map[string]string `json:"tags,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Referrers []OCIReferrer     `json:"referrers,omitempty"`
}
type OCIPublication struct {
	Image, Reference string
	Objects          []Artifact
	Tags             map[string]string
	CompleteTags     bool
	MemberCaches     map[string]OCIMemberCache
}

func insertOCIObject(ctx context.Context, tx pgx.Tx, i Identity, repo string, a Artifact) error {
	if e := notDeletedInTx(ctx, tx, repo, a.Path); e != nil {
		return e
	}
	if a.Metadata == nil {
		a.Metadata = json.RawMessage(`{}`)
	}
	_, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, i.Tenant, repo, a.Path, a.Digest, a.Size, a.MediaType, a.Metadata)
	if e != nil {
		return e
	}
	var digest, media string
	var size int64
	if e = tx.QueryRow(ctx, `SELECT digest,size,media_type FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, a.Path).Scan(&digest, &size, &media); e != nil {
		return e
	}
	if digest != a.Digest || size != a.Size || media != a.MediaType {
		return ErrConflict
	}
	_, e = tx.Exec(ctx, `UPDATE cratectl.artifacts SET source_revision=(SELECT source_revision FROM cratectl.repositories WHERE name=$1) WHERE repository=$1 AND path=$2`, repo, a.Path)
	return e
}
func completeOCIPublication(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, lease Retrieval, p OCIPublication, objectDigest string, objectSize int64, fresh, stale int, sequence int64) error {
	if repo.Format != "oci" || len(p.Objects) > 4096 || p.Image == "" {
		return ErrConflict
	}
	if strings.HasPrefix(lease.Path, "oci-catalog/") && lease.Path != "oci-catalog/"+p.Image+"/tags" && !strings.HasPrefix(lease.Path, "oci-catalog/"+p.Image+"/referrers/sha256:") {
		return ErrConflict
	}
	seen := map[string]bool{}
	observation := strings.HasPrefix(lease.Path, "oci-catalog/")
	retired := map[string]bool{}
	accepted := []Artifact{}
	for _, a := range p.Objects {
		if seen[a.Path] || (a.Path != p.Image+"/blobs/sha256:"+a.Digest && a.Path != p.Image+"/manifests/sha256:"+a.Digest) {
			return ErrConflict
		}
		if a.Path == p.Image+"/manifests/sha256:"+a.Digest && !isManifest(a.MediaType) {
			return ErrConflict
		}
		seen[a.Path] = true
		if observation {
			if e := notDeletedInTx(ctx, tx, repo.Name, a.Path); errors.Is(e, ErrDeleted) {
				var digest, media string
				var size int64
				if e = tx.QueryRow(ctx, `SELECT digest,size,media_type FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo.Name, a.Path).Scan(&digest, &size, &media); e != nil {
					return e
				}
				if digest != a.Digest || size != a.Size || media != a.MediaType {
					return ErrConflict
				}
				retired[a.Path] = true
				continue
			} else if e != nil {
				return e
			}
		}
		if e := insertOCIObject(ctx, tx, i, repo.Name, a); e != nil {
			return e
		}
		accepted = append(accepted, a)
	}
	for _, a := range p.Objects {
		if retired[a.Path] {
			continue
		}
		c, ok := p.MemberCaches[a.Path]
		if !ok {
			c = OCIMemberCache{FreshSeconds: fresh, StaleSeconds: stale}
		}
		if e := refreshOCIMember(ctx, tx, i, lease, a, c, sequence); e != nil {
			return e
		}
	}
	for _, a := range p.Objects {
		if retired[a.Path] {
			continue
		}
		if isManifest(a.MediaType) {
			var m OCIManifestMetadata
			if json.Unmarshal(a.Metadata, &m) != nil || !m.Validated {
				return ErrConflict
			}
			if observation {
				if m.References == nil || len(m.References) > 4096 || len(m.Descriptors) > 4096 {
					return ErrConflict
				}
				for _, path := range m.References {
					d, ok := m.Descriptors[path]
					if !ok || d.Size < 0 || !strings.HasPrefix(d.Digest, "sha256:") || !uploadDigest.MatchString(strings.TrimPrefix(d.Digest, "sha256:")) || (path != p.Image+"/blobs/"+d.Digest && path != p.Image+"/manifests/"+d.Digest) {
						return ErrConflict
					}
				}
				if _, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=$1 WHERE repository=$2 AND path=$3 AND digest=$4`, a.Metadata, repo.Name, a.Path, a.Digest); e != nil {
					return e
				}
			} else if e := publishOCI(ctx, tx, i, repo.Name, p.Image, "", a, m); e != nil {
				return e
			}
		}
	}
	if observation {
		// A source advertisement is intake, not current serving permission. Verify
		// the retained structure in one snapshot while preserving every decision
		// and tombstone. Ordinary reads still evaluate the complete current graph.
		budget := newGraphBudget()
		budget.retained = true
		budget.observation = true
		for _, a := range accepted {
			if isManifest(a.MediaType) {
				if _, e := readArtifact(ctx, tx, repo.Name, a.Path, false, budget); e != nil {
					return e
				}
			}
		}
	}
	if p.Reference != "" {
		if lease.Path != p.Image+"/manifests/"+p.Reference {
			return ErrConflict
		}
		digest := p.Reference
		if !strings.HasPrefix(digest, "sha256:") {
			digest = p.Tags[p.Reference]
		}
		if digest != "sha256:"+objectDigest {
			return ErrConflict
		}
		exists := seen[p.Image+"/manifests/"+digest]
		if !exists {
			return ErrConflict
		}
	} else if !strings.HasPrefix(lease.Path, "oci-catalog/") {
		if lease.Path != p.Image+"/blobs/sha256:"+objectDigest || !seen[lease.Path] {
			return ErrConflict
		}
	}
	if p.Reference != "" || !strings.HasPrefix(lease.Path, "oci-catalog/") {
		found := false
		for _, a := range p.Objects {
			if a.Digest == objectDigest && a.Size == objectSize {
				found = true
				break
			}
		}
		if !found {
			return ErrConflict
		}
	}
	if p.CompleteTags {
		if lease.Path != "oci-catalog/"+p.Image+"/tags" {
			return ErrConflict
		}
		names := []string{}
		for tag := range p.Tags {
			names = append(names, tag)
		}
		var newer bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.tags WHERE repository=$1 AND image=$2 AND NOT(tag=ANY($3::text[])) AND NOT deleted AND change_sequence>$4)`, repo.Name, p.Image, names, lease.ChangeSequence).Scan(&newer); e != nil {
			return e
		}
		if newer {
			return ErrOCIMemberChanged
		}
		if _, e := tx.Exec(ctx, `UPDATE cratectl.tags SET deleted=true,version=version+1,changed_at=clock_timestamp(),change_sequence=$4,source_revision=$5 WHERE repository=$1 AND image=$2 AND NOT(tag=ANY($3::text[])) AND (NOT deleted OR source_revision<>$5)`, repo.Name, p.Image, names, sequence, lease.SourceRevision); e != nil {
			return e
		}
	}
	for tag, digest := range p.Tags {
		if !seen[p.Image+"/manifests/"+digest] {
			return ErrConflict
		}
		var previous string
		var deleted bool
		var changed int64
		e := tx.QueryRow(ctx, `SELECT digest,deleted,change_sequence FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3`, repo.Name, p.Image, tag).Scan(&previous, &deleted, &changed)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil && changed > lease.ChangeSequence {
			if previous == digest && !deleted {
				continue
			}
			return ErrOCIMemberChanged
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.tags(tenant,repository,image,tag,digest,change_sequence,source_revision) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant,repository,image,tag) DO UPDATE SET digest=excluded.digest,deleted=false,version=cratectl.tags.version+1,changed_at=clock_timestamp(),change_sequence=excluded.change_sequence,source_revision=excluded.source_revision`, i.Tenant, repo.Name, p.Image, tag, digest, sequence, lease.SourceRevision); e != nil {
			return e
		}
	}
	return enqueueIntegrity(ctx, tx, i, repo.Name, accepted)
}
func ociCacheInTx(ctx context.Context, tx pgx.Tx, repo, path string, admissions ...OCIAdmission) (bool, error) {
	var r Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo, path), &r)
	if errors.Is(e, pgx.ErrNoRows) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	var revision int64
	if e = tx.QueryRow(ctx, `SELECT source_revision FROM cratectl.repositories WHERE name=$1`, repo).Scan(&revision); e != nil {
		return false, e
	}
	if r.SourceRevision != revision {
		return false, ErrSourceChanged
	}
	if r.State == "fetching" {
		return false, ErrBusy
	}
	if r.State == "negative" {
		if !r.Fresh() {
			return false, ErrOCICacheExpired
		}
		return false, nil
	}
	if r.State == "failed" {
		if r.StalePermitted() {
			admitted, e := ociCacheAdmission(ctx, tx, repo, r, admissions)
			if e != nil {
				return false, e
			}
			if admitted {
				return true, nil
			}
		}
		if !r.Fresh() {
			return false, ErrOCICacheExpired
		}
		return false, ErrOCICache
	}
	if r.State == "ready" && !r.Fresh() {
		admitted, e := ociCacheAdmission(ctx, tx, repo, r, admissions)
		if e != nil {
			return false, e
		}
		if !admitted {
			return false, ErrOCICacheExpired
		}
	}
	return true, nil
}

// OCISelection checks source precedence, all selected grants and the complete
// graph from one snapshot. A known but blocked first source owns the collision.
func (s *Store) OCISelection(ctx context.Context, i Identity, repo, image, kind, ref string, admissions ...OCIAdmission) (Artifact, Repository, error) {
	return s.ociSelection(ctx, i, repo, image, kind, ref, nil, admissions...)
}

func (s *Store) OCISelectionAtRevision(ctx context.Context, i Identity, repo, image, kind, ref string, snapshot SourceSnapshot, admissions ...OCIAdmission) (Artifact, Repository, error) {
	return s.ociSelection(ctx, i, repo, image, kind, ref, &snapshot, admissions...)
}

func (s *Store) ociSelection(ctx context.Context, i Identity, repo, image, kind, ref string, snapshot *SourceSnapshot, admissions ...OCIAdmission) (Artifact, Repository, error) {
	var a Artifact
	var selected Repository
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if snapshot != nil {
			source, e := repositoryInTx(ctx, tx, i, snapshot.Repository, "read")
			if e != nil {
				return e
			}
			if _, e = checkSourceSnapshot(ctx, tx, i, source, *snapshot); e != nil {
				return e
			}
		}
		endpoint, members, e := nativeRepositories(ctx, tx, i, repo, image, "oci")
		if e != nil {
			return e
		}
		for _, source := range members {
			digest := ref
			if e = ociReferenceLifecycleInTx(ctx, tx, source, image, kind, ref); e != nil {
				return e
			}
			if source.Mode == "proxy" {
				valid, e := ociCacheInTx(ctx, tx, source.Name, image+"/"+kind+"/"+ref, admissions...)
				if e != nil {
					return e
				}
				if !valid {
					continue
				}
			}
			if kind == "manifests" && !strings.HasPrefix(ref, "sha256:") {
				var deleted bool
				var revision int64
				e = tx.QueryRow(ctx, `SELECT digest,deleted,source_revision FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3`, source.Name, image, ref).Scan(&digest, &deleted, &revision)
				if errors.Is(e, pgx.ErrNoRows) {
					continue
				}
				if e != nil {
					return e
				}
				if source.Mode == "proxy" && revision != source.SourceRevision {
					return ErrSourceChanged
				}
				if deleted {
					if source.Mode == "hosted" {
						return ErrDeleted
					}
					continue
				}
			}
			p := image + "/" + kind + "/" + digest
			var exists bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, source.Name, p).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				if digest != ref {
					return ErrDenied
				}
				continue
			}
			selected = source
			a, e = readArtifact(ctx, tx, source.Name, p, endpoint.RequireReview || source.RequireReview, ociGraphBudget(source, admissions))
			if errors.Is(e, ErrNotFound) {
				return ErrDenied
			}
			return e
		}
		return ErrNotFound
	})
	return a, selected, e
}
