// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"ctlplne.dev/cratectl/internal/cargo"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var errCargoCoordinateChanged = errors.New("upstream Cargo version changed its retained source binding")

const cargoSubmittedSources = `WITH submitted AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS d(key text,format text,name text,coordinate text,version text,url text,integrity text,metadata jsonb)
) `

// A source revision retains each version binding even when it drops out of an
// index. Compare all rows before inserting so a conflict cannot commit half of
// a publication. The caller holds the shared tenant mutation lock.
func completeCargoCatalog(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, lease Retrieval, result RetrievalResult) error {
	name := strings.TrimPrefix(lease.Path, "cargo-catalog/")
	nameKey, e := cargo.NameKey(name)
	if e != nil || name != nameKey || result.CargoBinding != nil {
		return ErrCargoUnvalidated
	}
	if result.Status == 304 {
		_, _, e = cargoCatalogInTx(ctx, tx, repo, name)
		return e
	}
	publication := result.NativeCatalog
	var catalog CargoCatalog
	if publication == nil || publication.Name != name || result.MediaType != CargoCatalogMedia || result.Object == nil ||
		result.Object.Size != int64(len(result.Metadata)) || len(result.Metadata) > 32<<20 || crypt.Digest(result.Metadata) != result.Object.Digest ||
		json.Unmarshal(result.Metadata, &catalog) != nil || catalog.Name != name || len(catalog.Entries) == 0 || len(catalog.Entries) > 10000 ||
		len(publication.Sources) != len(catalog.Entries) || len(publication.Entries) != len(catalog.Entries) {
		return ErrCargoUnvalidated
	}
	seen := map[string]bool{}
	for n, entry := range catalog.Entries {
		source := publication.Sources[n]
		versionKey, e := cargo.VersionKey(entry.Version)
		canonical, marshalErr := CargoCanonicalSource(entry)
		if e != nil || marshalErr != nil || seen[versionKey] || source.Coordinate != versionKey || source.Format != "cargo" ||
			source.Name != name || !strings.EqualFold(entry.Name, name) || source.Version != entry.Version ||
			source.Key != CargoSourceKey(name, entry.Version) || publication.Entries[versionKey] != source.Key ||
			source.Integrity != "sha256:"+entry.Checksum || !cargoDigest.MatchString(entry.Checksum) ||
			len(source.URL) == 0 || len(source.URL) > 2048 || string(source.Metadata) != string(canonical) {
			return ErrCargoUnvalidated
		}
		seen[versionKey] = true
	}
	data, e := json.Marshal(publication.Sources)
	if e != nil || len(data) > 56<<20 {
		return ErrMetadataLimit
	}
	var changed bool
	e = tx.QueryRow(ctx, cargoSubmittedSources+`SELECT EXISTS(SELECT 1 FROM submitted d JOIN cratectl.native_sources s
 ON (s.repository,s.source_revision,s.key)=($2,$3,d.key)
 WHERE (s.format,s.package,s.coordinate,s.version,s.url,s.integrity,s.metadata)
 IS DISTINCT FROM (d.format,d.name,d.coordinate,d.version,d.url,d.integrity,d.metadata))`, data, repo.Name, lease.SourceRevision).Scan(&changed)
	if e != nil {
		return e
	}
	if changed {
		return errCargoCoordinateChanged
	}
	_, e = tx.Exec(ctx, cargoSubmittedSources+`INSERT INTO cratectl.native_sources(tenant,repository,key,format,package,coordinate,version,url,integrity,metadata,source_revision)
 SELECT $4,$2,key,format,name,coordinate,version,url,integrity,metadata,$3 FROM submitted ON CONFLICT DO NOTHING`, data, repo.Name, lease.SourceRevision, i.Tenant)
	return e
}

func CargoProxyCoordinate(p string) (name, version string, ok bool) {
	name, version, ok = strings.Cut(strings.TrimPrefix(p, "crates/"), "/")
	version = strings.TrimSuffix(version, ".crate")
	expected, e := CargoProxyPath(name, version)
	return name, version, ok && e == nil && p == expected
}

func completeCargoArchive(ctx context.Context, tx pgx.Tx, repo Repository, lease Retrieval, result RetrievalResult) error {
	name, version, ok := CargoProxyCoordinate(lease.Path)
	if !ok || result.NativeCatalog != nil || result.CargoBinding == nil {
		return ErrCargoUnvalidated
	}
	binding, _, e := cargoArchiveBindingInTx(ctx, tx, repo, name, version)
	if e != nil {
		return e
	}
	if binding != *result.CargoBinding {
		return ErrSourceChanged
	}
	var a Artifact
	if result.Status == 304 {
		a, e = readArtifact(ctx, tx, repo.Name, lease.Path, false, repositoryReadBudget(repo))
		if e != nil {
			return e
		}
	} else {
		if result.Object == nil || len(result.Metadata) > 4096 {
			return ErrCargoUnvalidated
		}
		a = Artifact{Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
	}
	if !validCargoArchive(a, binding) {
		return ErrCargoUnvalidated
	}
	return nil
}
