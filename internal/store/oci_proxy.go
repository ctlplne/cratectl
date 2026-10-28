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
}

func insertOCIObject(ctx context.Context, tx pgx.Tx, i Identity, repo string, a Artifact) error {
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
	return nil
}
func completeOCIPublication(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, lease Retrieval, p OCIPublication, objectDigest string, objectSize int64) error {
	if repo.Format != "oci" || len(p.Objects) > 4096 || p.Image == "" {
		return ErrConflict
	}
	if strings.HasPrefix(lease.Path, "oci-catalog/") && lease.Path != "oci-catalog/"+p.Image+"/tags" && !strings.HasPrefix(lease.Path, "oci-catalog/"+p.Image+"/referrers/sha256:") {
		return ErrConflict
	}
	seen := map[string]bool{}
	for _, a := range p.Objects {
		if seen[a.Path] || (a.Path != p.Image+"/blobs/sha256:"+a.Digest && a.Path != p.Image+"/manifests/sha256:"+a.Digest) {
			return ErrConflict
		}
		if a.Path == p.Image+"/manifests/sha256:"+a.Digest && !isManifest(a.MediaType) {
			return ErrConflict
		}
		seen[a.Path] = true
		if e := insertOCIObject(ctx, tx, i, repo.Name, a); e != nil {
			return e
		}
	}
	for _, a := range p.Objects {
		if isManifest(a.MediaType) {
			var m OCIManifestMetadata
			if json.Unmarshal(a.Metadata, &m) != nil || !m.Validated {
				return ErrConflict
			}
			if e := publishOCI(ctx, tx, i, repo.Name, p.Image, "", a, m); e != nil {
				return e
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
		if _, e := tx.Exec(ctx, `UPDATE cratectl.tags SET deleted=true,version=version+1 WHERE repository=$1 AND image=$2 AND NOT(tag=ANY($3::text[])) AND NOT deleted`, repo.Name, p.Image, names); e != nil {
			return e
		}
	}
	for tag, digest := range p.Tags {
		if !seen[p.Image+"/manifests/"+digest] {
			return ErrConflict
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.tags(tenant,repository,image,tag,digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,repository,image,tag) DO UPDATE SET digest=excluded.digest,deleted=false,version=cratectl.tags.version+1`, i.Tenant, repo.Name, p.Image, tag, digest); e != nil {
			return e
		}
	}
	return nil
}
func ociCacheInTx(ctx context.Context, tx pgx.Tx, repo, path string) (bool, error) {
	var r Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo, path), &r)
	if errors.Is(e, pgx.ErrNoRows) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if r.State == "negative" {
		return false, nil
	}
	if r.State == "failed" && !r.StalePermitted() {
		return false, ErrOCICache
	}
	return true, nil
}

// OCISelection checks source precedence, all selected grants and the complete
// graph from one snapshot. A known but blocked first source owns the collision.
func (s *Store) OCISelection(ctx context.Context, i Identity, repo, image, kind, ref string) (Artifact, Repository, error) {
	var a Artifact
	var selected Repository
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		endpoint, members, e := nativeRepositories(ctx, tx, i, repo, image, "oci")
		if e != nil {
			return e
		}
		for _, source := range members {
			digest := ref
			if source.Mode == "proxy" {
				valid, e := ociCacheInTx(ctx, tx, source.Name, image+"/"+kind+"/"+ref)
				if e != nil {
					return e
				}
				if !valid {
					continue
				}
			}
			if kind == "manifests" && !strings.HasPrefix(ref, "sha256:") {
				e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3 AND NOT deleted`, source.Name, image, ref).Scan(&digest)
				if errors.Is(e, pgx.ErrNoRows) {
					continue
				}
				if e != nil {
					return e
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
			a, e = readArtifact(ctx, tx, source.Name, p, endpoint.RequireReview || source.RequireReview, newGraphBudget())
			if errors.Is(e, ErrNotFound) {
				return ErrDenied
			}
			return e
		}
		return ErrNotFound
	})
	return a, selected, e
}
