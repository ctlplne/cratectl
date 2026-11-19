// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"strings"

	"ctlplne.dev/cratectl/internal/composer"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

const ComposerCatalogMedia = "application/vnd.cratectl.composer.catalog+json"

type ComposerProxyCatalog struct {
	Name          string                        `json:"name"`
	Development   bool                          `json:"development"`
	Distributions []composer.RemoteDistribution `json:"distributions"`
}

func ComposerCatalogPath(name string, development bool) string {
	path := "composer-catalog/" + name
	if development {
		path += "~dev"
	}
	return path
}

func ParseComposerCatalogPath(path string) (name string, development, ok bool) {
	name, ok = strings.CutPrefix(path, "composer-catalog/")
	name, development = strings.CutSuffix(name, "~dev")
	return name, development, ok && composer.ValidName(name)
}

func ComposerProxyArchivePath(coordinate composer.Coordinate, digest string) string {
	return "composer-cache/" + digest + "/" + coordinate.Path()
}

func ParseComposerProxyArchive(path string) (composer.Coordinate, string, bool) {
	remaining, prefixed := strings.CutPrefix(path, "composer-cache/")
	digest, relative, found := strings.Cut(remaining, "/")
	coordinate, valid := composer.ParseDistribution(relative)
	return coordinate, digest, prefixed && found && valid && uploadDigest.MatchString(digest)
}

func decodeComposerCatalog(a Artifact, limit int, byteLimit int64) (ComposerProxyCatalog, error) {
	var catalog ComposerProxyCatalog
	name, development, valid := ParseComposerCatalogPath(a.Path)
	if !valid || a.MediaType != ComposerCatalogMedia || !uploadDigest.MatchString(a.Digest) ||
		len(a.Metadata) == 0 || int64(len(a.Metadata)) > min(byteLimit, composer.CatalogBytes) ||
		json.Unmarshal(a.Metadata, &catalog) != nil || catalog.Name != name || catalog.Development != development ||
		catalog.Distributions == nil || len(catalog.Distributions) > min(limit, 10000) {
		return ComposerProxyCatalog{}, ErrConflict
	}
	versions := make(map[string]bool, len(catalog.Distributions))
	for _, entry := range catalog.Distributions {
		coordinate := entry.Coordinate()
		if coordinate.Name != name || coordinate.Development() != development ||
			!uploadDigest.MatchString(entry.SHA256) || !entry.ValidFor(coordinate) || versions[coordinate.Version] {
			return ComposerProxyCatalog{}, ErrConflict
		}
		versions[coordinate.Version] = true
	}
	return catalog, nil
}

func composerReadCatalog(ctx context.Context, tx pgx.Tx, r Repository, name string, development bool, limit int, byteLimit int64,
	admissions []NativeAdmission) (Artifact, ComposerProxyCatalog, error) {
	path := ComposerCatalogPath(name, development)
	state, err := nativeCatalogRetrieval(ctx, tx, r.Name, path)
	if err != nil {
		return Artifact{}, ComposerProxyCatalog{}, err
	}
	if state.State != "ready" || state.SourceRevision != r.SourceRevision || (!state.Fresh() && !nativeGenerationAdmitted(state, admissions, false)) {
		return Artifact{}, ComposerProxyCatalog{}, ErrSourceChanged
	}
	budget := repositoryReadBudget(r)
	budget.sqlMetadataBytes = min(byteLimit, composer.CatalogBytes)
	a, err := readArtifact(ctx, tx, r.Name, path, false, budget)
	if err != nil {
		return a, ComposerProxyCatalog{}, err
	}
	catalog, err := decodeComposerCatalog(a, limit, byteLimit)
	return a, catalog, err
}

// ComposerProxyVersions filters one admitted catalog using current package
// decisions and retained lifecycle. Its URLs continue to pin exact SHA-256.
func (s *Store) ComposerProxyVersions(ctx context.Context, i Identity, repo Repository, a Artifact,
	limit int, byteLimit int64, admissions []NativeAdmission) ([]composer.RemoteDistribution, error) {
	var out []composer.RemoteDistribution
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo.Name, "read")
		if err != nil {
			return err
		}
		if r.Format != "composer" || r.Mode != "proxy" || r.SourceRevision != repo.SourceRevision {
			return ErrSourceChanged
		}
		name, development, ok := ParseComposerCatalogPath(a.Path)
		if !ok {
			return ErrConflict
		}
		current, catalog, err := composerReadCatalog(ctx, tx, r, name, development, limit, byteLimit, admissions)
		if err != nil {
			return err
		}
		if current.Digest != a.Digest {
			return ErrSourceChanged
		}
		paths := make([]string, 0, len(catalog.Distributions))
		digests := make([]string, 0, len(catalog.Distributions))
		installations := make([]string, 0, len(catalog.Distributions))
		for _, entry := range catalog.Distributions {
			paths = append(paths, ComposerProxyArchivePath(entry.Coordinate(), entry.SHA256))
			digests = append(digests, entry.SHA256)
			installation := entry.Package
			installation.Description = ""
			data, err := json.Marshal(installation)
			if err != nil {
				return err
			}
			installations = append(installations, string(data))
		}
		rows, err := tx.Query(ctx, `SELECT requested.position
FROM unnest($1::text[],$2::text[],$3::text[]) WITH ORDINALITY AS requested(path,digest,installation,position)
LEFT JOIN cratectl.artifacts a ON (a.tenant,a.repository,a.path,a.source_revision)=($4,$5,requested.path,$6)
LEFT JOIN cratectl.content_decisions d ON (d.tenant,d.repository,d.digest)=($4,$5,requested.digest)
LEFT JOIN cratectl.artifact_lifecycle l ON (l.tenant,l.repository,l.path)=($4,$5,requested.path)
LEFT JOIN cratectl.retrievals cached ON (cached.tenant,cached.repository,cached.path,cached.source_revision)=($4,$5,requested.path,$6)
WHERE NOT COALESCE(l.deleted,false) AND COALESCE(d.decision,a.decision,'unassessed')<>'denied'
 AND NOT COALESCE(cached.state IN ('negative','failed'),false)
 AND (a.path IS NULL OR ((a.metadata->'package')-'description')=requested.installation::jsonb)
 AND (NOT $7::boolean OR (COALESCE(d.decision,a.decision)='allowed' AND a.digest=requested.digest AND
      a.metadata->>'archive_validated'='true' AND cached.state='ready' AND cached.fresh_until>clock_timestamp()))
ORDER BY requested.position`, paths, digests, installations, i.Tenant, r.Name, r.SourceRevision, r.RequireReview)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var position int
			if err := rows.Scan(&position); err != nil {
				return err
			}
			if position < 1 || position > len(catalog.Distributions) {
				return ErrConflict
			}
			out = append(out, catalog.Distributions[position-1])
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(out) == 0 {
			return ErrNotFound
		}
		return nil
	})
	return out, err
}

func composerProxyBinding(ctx context.Context, tx pgx.Tx, r Repository, coordinate composer.Coordinate, digest string, catalogDigest string,
	limit int, byteLimit int64, admissions []NativeAdmission) (composer.RemoteDistribution, error) {
	a, catalog, err := composerReadCatalog(ctx, tx, r, coordinate.Name, coordinate.Development(), limit, byteLimit, admissions)
	if err != nil {
		return composer.RemoteDistribution{}, err
	}
	if catalogDigest != "" && a.Digest != catalogDigest {
		return composer.RemoteDistribution{}, ErrSourceChanged
	}
	for _, entry := range catalog.Distributions {
		if entry.Coordinate() == coordinate {
			if entry.SHA256 != digest {
				return composer.RemoteDistribution{}, ErrConflict
			}
			return entry, nil
		}
	}
	return composer.RemoteDistribution{}, ErrNotFound
}

func (s *Store) ComposerProxyBinding(ctx context.Context, i Identity, repo Repository, coordinate composer.Coordinate, digest, catalogDigest string,
	limit int, byteLimit int64, admissions []NativeAdmission) (composer.RemoteDistribution, error) {
	var entry composer.RemoteDistribution
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo.Name, "read")
		if err != nil {
			return err
		}
		if r.Format != "composer" || r.Mode != "proxy" || r.SourceRevision != repo.SourceRevision {
			return ErrSourceChanged
		}
		if err := notDeletedInTx(ctx, tx, repo.Name, ComposerProxyArchivePath(coordinate, digest)); err != nil {
			return err
		}
		decision := ""
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT decision FROM cratectl.content_decisions WHERE repository=$1 AND digest=$2),'')`,
			repo.Name, digest).Scan(&decision); err != nil {
			return err
		}
		if decision == "denied" {
			return ErrDenied
		}
		entry, err = composerProxyBinding(ctx, tx, r, coordinate, digest, catalogDigest, limit, byteLimit, admissions)
		return err
	})
	return entry, err
}

func (s *Store) ComposerProxyArtifact(ctx context.Context, i Identity, repo Repository, path, catalogDigest string, limit int, byteLimit int64,
	admissions []NativeAdmission) (Artifact, error) {
	var artifact Artifact
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo.Name, "read")
		if err != nil {
			return err
		}
		if r.Format != "composer" || r.Mode != "proxy" || r.SourceRevision != repo.SourceRevision {
			return ErrSourceChanged
		}
		coordinate, digest, valid := ParseComposerProxyArchive(path)
		if !valid {
			return ErrConflict
		}
		state, err := nativeCatalogRetrieval(ctx, tx, r.Name, path)
		if err != nil {
			return err
		}
		if state.State != "ready" || state.SourceRevision != r.SourceRevision || (!state.Fresh() && !nativeGenerationAdmitted(state, admissions, false)) {
			return ErrSourceChanged
		}
		budget := repositoryReadBudget(r)
		budget.sqlMetadataBytes = composerMetadataBytes
		artifact, err = readArtifact(ctx, tx, r.Name, path, r.RequireReview, budget)
		if err != nil {
			return err
		}
		current, err := decodeComposerPackage(artifact)
		if err != nil {
			return err
		}
		if catalogDigest != "" {
			entry, err := composerProxyBinding(ctx, tx, r, coordinate, digest, catalogDigest, limit, byteLimit, admissions)
			if err != nil {
				return err
			}
			if (entry.SHA1 != "" && entry.SHA1 != current.SHA1) || !entry.Package.SameInstallation(current.Package) {
				return ErrConflict
			}
		}
		return nil
	})
	return artifact, err
}

func validateComposerRetrieval(lease Retrieval, result RetrievalResult) error {
	if result.Object == nil || result.Status != 200 || result.Failure != "" {
		return nil
	}
	a := Artifact{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
	if _, _, ok := ParseComposerCatalogPath(lease.Path); ok {
		if a.Size != int64(len(result.Metadata)) || crypt.Digest(result.Metadata) != a.Digest {
			return ErrConflict
		}
		_, err := decodeComposerCatalog(a, 10000, composer.CatalogBytes)
		return err
	}
	if _, _, ok := ParseComposerProxyArchive(lease.Path); !ok {
		return ErrConflict
	}
	_, err := decodeComposerPackage(a)
	return err
}
