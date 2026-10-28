// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"
)

func (s *Store) OCIDiscovery(ctx context.Context, i Identity, repo, image, kind, subject, filter string, limit int, byteLimit int64, admissions ...OCIAdmission) ([]string, []OCIReferrer, error) {
	tags := []string{}
	referrers := []OCIReferrer{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		endpoint, members, e := nativeRepositories(ctx, tx, i, repo, image, "oci")
		if e != nil {
			return e
		}
		if limit <= 0 || byteLimit <= 0 {
			return ErrConflict
		}
		seen := map[string]bool{}
		total := 0
		var metadataBytes int64
		if kind == "referrers" {
			for _, source := range members {
				var exists bool
				if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, source.Name, image+"/manifests/"+subject).Scan(&exists); e != nil {
					return e
				}
				if !exists {
					continue
				}
				if _, e = readArtifact(ctx, tx, source.Name, image+"/manifests/"+subject, endpoint.RequireReview || source.RequireReview, ociGraphBudget(source, admissions)); e != nil {
					return e
				}
				break
			}
		}
		for _, source := range members {
			var catalog *OCICatalog
			if source.Mode == "proxy" {
				suffix := "tags"
				if kind == "referrers" {
					suffix = "referrers/" + subject
				}
				name := image + "/" + suffix
				valid, e := ociCacheInTx(ctx, tx, source.Name, "oci-catalog/"+name, admissions...)
				if e != nil {
					return e
				}
				if !valid {
					continue
				}
				a, e := nativeCatalogArtifact(ctx, tx, i, source.Name, name, "oci", OCICatalogMedia)
				if errors.Is(e, ErrNotFound) {
					continue
				}
				if e != nil {
					return e
				}
				var c OCICatalog
				if json.Unmarshal(a.Metadata, &c) != nil || c.Image != image {
					return ErrConflict
				}
				catalog = &c
			}
			type candidate struct{ name, digest, path string }
			candidates := []candidate{}
			if kind == "tags/list" {
				rows, e := tx.Query(ctx, `SELECT tag,digest FROM cratectl.tags WHERE repository=$1 AND image=$2 AND NOT deleted ORDER BY tag LIMIT $3`, source.Name, image, limit+1)
				if e != nil {
					return e
				}
				for rows.Next() {
					var c candidate
					if e = rows.Scan(&c.name, &c.digest); e != nil {
						rows.Close()
						return e
					}
					c.path = image + "/manifests/" + c.digest
					candidates = append(candidates, c)
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					return e
				}
			} else if catalog != nil {
				for _, d := range catalog.Referrers {
					candidates = append(candidates, candidate{name: d.Digest, digest: d.Digest, path: image + "/manifests/" + d.Digest})
				}
			} else {
				rows, e := tx.Query(ctx, `SELECT path,digest,octet_length(metadata::text) FROM cratectl.artifacts WHERE repository=$1 AND starts_with(path,$2) AND metadata->'oci_subject'->>'digest'=$3 ORDER BY path LIMIT $4`, source.Name, image+"/manifests/", subject, limit+1)
				if e != nil {
					return e
				}
				for rows.Next() {
					var c candidate
					var size int64
					if e = rows.Scan(&c.path, &c.digest, &size); e != nil {
						rows.Close()
						return e
					}
					c.name = "sha256:" + c.digest
					metadataBytes += size
					candidates = append(candidates, c)
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					return e
				}
			}
			for _, c := range candidates {
				if seen[c.name] {
					continue
				}
				total++
				if total > limit || metadataBytes > byteLimit {
					return ErrMetadataLimit
				}
				seen[c.name] = true
				a, e := readArtifact(ctx, tx, source.Name, c.path, source.RequireReview || endpoint.RequireReview, ociGraphBudget(source, admissions))
				if errors.Is(e, ErrDenied) || errors.Is(e, ErrNotFound) {
					continue
				}
				if e != nil {
					return e
				}
				if kind == "tags/list" {
					tags = append(tags, c.name)
					continue
				}
				var metadata OCIManifestMetadata
				if json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated || metadata.Subject == nil || metadata.Subject.Digest != subject {
					return ErrConflict
				}
				if filter == "" || filter == metadata.ArtifactType {
					referrers = append(referrers, OCIReferrer{OCIDescriptor{a.MediaType, "sha256:" + a.Digest, a.Size}, metadata.ArtifactType, metadata.Annotations})
				}
			}
		}
		return nil
	})
	sort.Strings(tags)
	sort.Slice(referrers, func(a, b int) bool { return referrers[a].Digest < referrers[b].Digest })
	return tags, referrers, e
}
