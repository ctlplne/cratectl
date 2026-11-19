// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

const NuGetProxyCatalogMedia = "application/vnd.cratectl.nuget-versions+json"

// NuGetPackageBase is the explicitly configured package byte authority.
func (r Repository) NuGetPackageBase() *upstream.Config {
	if r.Settings.NuGetServiceIndex {
		if len(r.Settings.DownloadSources) != 1 {
			return nil
		}
		return &r.Settings.DownloadSources[0]
	}
	return r.Settings.Upstream
}

func NuGetProxyCatalogPath(id string) string { return "nuget-catalog/" + id }

type NuGetProxyCoordinate struct {
	ID, Version string
}

func ParseNuGetProxyCoordinate(path string) (NuGetProxyCoordinate, error) {
	coordinate := NuGetProxyCoordinate{}
	if id, found := strings.CutPrefix(path, "nuget-catalog/"); found {
		coordinate.ID = id
	} else if packagePath, found := strings.CutPrefix(path, "nuget-packages/"); found {
		id, file, _ := strings.Cut(packagePath, "/")
		version, ok := strings.CutSuffix(file, ".nupkg")
		normal, err := nuget.VersionKey(version)
		if !ok || err != nil || normal != version {
			return coordinate, ErrNuGetUnvalidated
		}
		coordinate.ID, coordinate.Version = id, version
	} else {
		return coordinate, ErrNuGetUnvalidated
	}
	id, err := nuget.IDKey(coordinate.ID)
	if err != nil || id != coordinate.ID {
		return coordinate, ErrNuGetUnvalidated
	}
	return coordinate, nil
}

type NuGetProxyCatalog struct {
	ID        string   `json:"id"`
	Authority string   `json:"source_authority"`
	Versions  []string `json:"versions"`
}

func decodeNuGetProxyCatalog(ctx context.Context, data []byte, id, authority string, limit int, byteLimit int64) (NuGetProxyCatalog, error) {
	var catalog NuGetProxyCatalog
	if int64(len(data)) > byteLimit || json.Unmarshal(data, &catalog) != nil || catalog.ID != id || catalog.Authority != authority ||
		catalog.Versions == nil || len(catalog.Versions) > limit {
		return catalog, ErrNuGetUnvalidated
	}
	for _, value := range catalog.Versions {
		version, err := nuget.VersionKey(value)
		if err != nil || version != value {
			return catalog, ErrNuGetUnvalidated
		}
	}
	sorted, err := nuget.SortVersionKeys(ctx, catalog.Versions)
	if err != nil || len(sorted) != len(catalog.Versions) {
		return catalog, ErrNuGetUnvalidated
	}
	for n, version := range sorted {
		if catalog.Versions[n] != version || (n > 0 && sorted[n-1] == version) {
			return catalog, ErrNuGetUnvalidated
		}
	}
	return catalog, nil
}

func validateNuGetRetrieval(ctx context.Context, repo Repository, lease Retrieval, result RetrievalResult) error {
	coordinate, err := ParseNuGetProxyCoordinate(lease.Path)
	base := repo.NuGetPackageBase()
	if err != nil || base == nil || result.Status != 200 || result.Object == nil {
		return ErrNuGetUnvalidated
	}
	if coordinate.Version == "" {
		if result.MediaType != NuGetProxyCatalogMedia || result.Object.Digest != crypt.Digest(result.Metadata) || result.Object.Size != int64(len(result.Metadata)) {
			return ErrNuGetUnvalidated
		}
		_, err := decodeNuGetProxyCatalog(ctx, result.Metadata, coordinate.ID, base.URL, 10000, 8<<20)
		return err
	}
	a := Artifact{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
	metadata, err := ValidateNuGetArtifact(ctx, a)
	if err != nil || metadata.SourceAuthority != base.URL || metadata.Catalog == nil || metadata.Catalog.SourceSHA != metadata.NuspecSHA256 {
		return ErrNuGetUnvalidated
	}
	return nil
}

// NuGetProxyVersions checks the retained catalog against the same current
// grants, source revision and digest policy used to serve exact package bytes.
func (s *Store) NuGetProxyVersions(ctx context.Context, i Identity, repo, id string, resolved Artifact, generation int64, limit int, byteLimit int64) ([]string, error) {
	key, err := nuget.IDKey(id)
	if err != nil || id != key || limit < 1 || byteLimit < 1 {
		return nil, ErrMetadataLimit
	}
	versions := []string{}
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		base := r.NuGetPackageBase()
		if r.Format != "nuget" || r.Mode != "proxy" || base == nil {
			return ErrConflict
		}
		a, err := nativeCatalogArtifact(ctx, tx, i, r.Name, id, "nuget", NuGetProxyCatalogMedia)
		if err != nil {
			return err
		}
		if a.Digest != resolved.Digest || a.SourceRevision != resolved.SourceRevision || a.SourceRevision != r.SourceRevision {
			return ErrSourceChanged
		}
		catalog, err := decodeNuGetProxyCatalog(ctx, a.Metadata, id, base.URL, min(limit, 10000), min(byteLimit, 8<<20))
		if err != nil {
			return err
		}
		state, err := nativeCatalogRetrieval(ctx, tx, r.Name, NuGetProxyCatalogPath(id))
		if err != nil {
			return err
		}
		// A no-cache response is valid for the request that filled it. Other
		// requests must always obtain a fresh admission from the resolver.
		if state.SourceRevision != r.SourceRevision || state.State != "ready" || state.Generation != generation {
			return ErrBusy
		}
		versions, err = nugetProxyVersionsInTx(ctx, tx, i, r, catalog, r.RequireReview)
		return err
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

func nugetProxyVersionsInTx(ctx context.Context, tx pgx.Tx, i Identity, r Repository, catalog NuGetProxyCatalog, review bool) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT requested.version
FROM unnest($1::text[]) WITH ORDINALITY AS requested(version,position)
LEFT JOIN cratectl.artifacts a ON (a.tenant,a.repository,a.path,a.source_revision)=($2,$3,'nuget-packages/'||$4||'/'||requested.version||'.nupkg',$5)
`+decisionJoin+`
LEFT JOIN cratectl.artifact_lifecycle l ON (l.tenant,l.repository,l.path)=($2,$3,'nuget-packages/'||$4||'/'||requested.version||'.nupkg')
LEFT JOIN cratectl.retrievals cached ON (cached.tenant,cached.repository,cached.path,cached.source_revision)=($2,$3,'nuget-packages/'||$4||'/'||requested.version||'.nupkg',$5)
WHERE NOT COALESCE(l.deleted,false) AND COALESCE(d.decision,a.decision,'unassessed')<>'denied'
 AND NOT COALESCE(cached.state IN ('negative','failed'),false)
 AND (NOT $6::boolean OR (COALESCE(d.decision,a.decision)='allowed' AND a.metadata->'archive_validated'='true'::jsonb
  AND a.metadata->>'source_authority'=$7 AND cached.state='ready' AND cached.fresh_until>clock_timestamp()))
ORDER BY requested.position`, catalog.Versions, i.Tenant, r.Name, catalog.ID, r.SourceRevision, review, catalog.Authority)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func nugetArchiveInTx(ctx context.Context, tx pgx.Tx, r Repository, path string, review bool, admissions []NativeAdmission) (Artifact, error) {
	if err := notDeletedInTx(ctx, tx, r.Name, path); err != nil {
		return Artifact{}, err
	}
	base := r.NuGetPackageBase()
	if r.Mode == "proxy" {
		if base == nil {
			return Artifact{}, ErrSourceChanged
		}
		state, err := nativeCatalogRetrieval(ctx, tx, r.Name, path)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && state.SourceRevision != r.SourceRevision) {
			return Artifact{}, ErrSourceChanged
		}
		if err != nil {
			return Artifact{}, err
		}
		ready := state.State == "ready" && (state.Fresh() || nativeGenerationAdmitted(state, admissions, false))
		stale := state.State == "failed" && state.StalePermitted() && nativeGenerationAdmitted(state, admissions, true)
		if !ready && !stale {
			return Artifact{}, ErrSourceChanged
		}
	}
	a, err := readArtifact(ctx, tx, r.Name, path, review, repositoryReadBudget(r))
	if err != nil {
		return a, err
	}
	metadata, err := ValidateNuGetArtifact(ctx, a)
	if err != nil {
		return a, err
	}
	if r.Mode == "proxy" && metadata.SourceAuthority != base.URL {
		return a, ErrSourceChanged
	}
	return a, nil
}

func (s *Store) NuGetProxyArtifact(ctx context.Context, i Identity, repo, path string, revision int64, admissions ...NativeAdmission) (Artifact, error) {
	var artifact Artifact
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "nuget" || r.Mode != "proxy" || r.SourceRevision != revision {
			return ErrSourceChanged
		}
		artifact, err = nugetArchiveInTx(ctx, tx, r, path, r.RequireReview, admissions)
		return err
	})
	return artifact, err
}
