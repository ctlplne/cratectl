// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"github.com/jackc/pgx/v5"
)

const NuGetProxyCatalogMedia = "application/vnd.cratectl.nuget-versions+json"

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
	if err != nil || repo.Settings.Upstream == nil || result.Status != 200 || result.Object == nil {
		return ErrNuGetUnvalidated
	}
	if coordinate.Version == "" {
		if result.MediaType != NuGetProxyCatalogMedia || result.Object.Digest != crypt.Digest(result.Metadata) || result.Object.Size != int64(len(result.Metadata)) {
			return ErrNuGetUnvalidated
		}
		_, err := decodeNuGetProxyCatalog(ctx, result.Metadata, coordinate.ID, repo.Settings.Upstream.URL, 10000, 8<<20)
		return err
	}
	a := Artifact{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
	metadata, err := ValidateNuGetArtifact(ctx, a)
	if err != nil || metadata.SourceAuthority != repo.Settings.Upstream.URL || metadata.Catalog == nil || metadata.Catalog.SourceSHA != metadata.NuspecSHA256 {
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
		if r.Format != "nuget" || r.Mode != "proxy" || r.Settings.Upstream == nil {
			return ErrConflict
		}
		a, err := nativeCatalogArtifact(ctx, tx, i, r.Name, id, "nuget", NuGetProxyCatalogMedia)
		if err != nil {
			return err
		}
		if a.Digest != resolved.Digest || a.SourceRevision != resolved.SourceRevision || a.SourceRevision != r.SourceRevision {
			return ErrSourceChanged
		}
		catalog, err := decodeNuGetProxyCatalog(ctx, a.Metadata, id, r.Settings.Upstream.URL, min(limit, 10000), min(byteLimit, 8<<20))
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
ORDER BY requested.position`, catalog.Versions, i.Tenant, r.Name, id, r.SourceRevision, r.RequireReview, r.Settings.Upstream.URL)
		if err != nil {
			return err
		}
		versions, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}
