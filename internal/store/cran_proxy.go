// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"ctlplne.dev/cratectl/internal/cran"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

const CRANProxyCatalogPath = "cran-catalog/source"
const CRANProxyCatalogMedia = "application/vnd.cratectl.cran.catalog+json"

func decodeCRANProxyCatalog(a Artifact, limit int, byteLimit int64) (map[string]cran.CatalogEntry, error) {
	var entries map[string]cran.CatalogEntry
	if a.Path != CRANProxyCatalogPath || a.MediaType != CRANProxyCatalogMedia || !uploadDigest.MatchString(a.Digest) ||
		len(a.Metadata) == 0 || int64(len(a.Metadata)) > min(byteLimit, cran.MaxCatalogBytes) ||
		json.Unmarshal(a.Metadata, &entries) != nil || entries == nil || len(entries) > min(limit, 10000) {
		return nil, ErrConflict
	}
	for path, entry := range entries {
		if !entry.Valid() || entry.Coordinate().Path() != path {
			return nil, ErrConflict
		}
	}
	return entries, nil
}

func validateCRANProxyArchive(a Artifact) (CRANPackage, error) {
	coordinate, digest, ok := cran.ParsePinnedSourcePath(a.Path)
	if !ok || a.Digest != digest {
		return CRANPackage{}, ErrConflict
	}
	a.Path = coordinate.Path()
	return ValidateCRANArtifact(a)
}

func checkCRANProxySource(ctx context.Context, tx pgx.Tx, i Identity, repo Repository) (Repository, error) {
	current, err := repositoryInTx(ctx, tx, i, repo.Name, "read")
	if err != nil {
		return current, err
	}
	if current.Format != "cran" || current.Mode != "proxy" || current.SourceRevision != repo.SourceRevision {
		return current, ErrSourceChanged
	}
	return current, nil
}

func checkCRANProxyGeneration(ctx context.Context, tx pgx.Tx, repo Repository, path string, admissions []NativeAdmission) error {
	state, err := nativeCatalogRetrieval(ctx, tx, repo.Name, path)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSourceChanged
	}
	if err != nil {
		return err
	}
	if state.State != "ready" || state.SourceRevision != repo.SourceRevision || (!state.Fresh() && !nativeGenerationAdmitted(state, admissions, false)) {
		return ErrSourceChanged
	}
	return nil
}

// CRANProxyIndex applies current digest decisions to one catalog admitted by
// the caller. It advertises only exact digest-bound archive locators.
func (s *Store) CRANProxyIndex(ctx context.Context, i Identity, repo Repository, expected string, limit int, byteLimit int64, admissions []NativeAdmission) (string, error) {
	byteLimit = min(byteLimit, cran.MaxCatalogBytes)
	var output strings.Builder
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		current, err := checkCRANProxySource(ctx, tx, i, repo)
		if err != nil {
			return err
		}
		if err := checkCRANProxyGeneration(ctx, tx, current, CRANProxyCatalogPath, admissions); err != nil {
			return err
		}
		budget := repositoryReadBudget(current)
		budget.sqlMetadataBytes = byteLimit
		a, err := readArtifact(ctx, tx, current.Name, CRANProxyCatalogPath, false, budget)
		if err != nil {
			return err
		}
		if a.Digest != expected {
			return ErrSourceChanged
		}
		catalog, err := decodeCRANProxyCatalog(a, limit, byteLimit)
		if err != nil {
			return err
		}
		files := make([]string, 0, len(catalog))
		for file := range catalog {
			files = append(files, file)
		}
		slices.Sort(files)
		paths, digests, requirements, md5s := make([]string, 0, len(files)), make([]string, 0, len(files)), make([]string, 0, len(files)), make([]string, 0, len(files))
		for _, file := range files {
			entry := catalog[file]
			paths = append(paths, cran.PinnedSourcePath(entry.Coordinate(), entry.SHA256))
			digests = append(digests, entry.SHA256)
			md5s = append(md5s, entry.MD5)
			encoded, err := json.Marshal(entry.Description)
			if err != nil {
				return err
			}
			requirements = append(requirements, string(encoded))
		}
		rows, err := tx.Query(ctx, `SELECT requested.position
FROM unnest($1::text[],$2::text[],$3::text[],$4::text[]) WITH ORDINALITY AS requested(path,digest,description,md5,position)
LEFT JOIN cratectl.artifacts a ON (a.tenant,a.repository,a.path,a.source_revision)=($5,$6,requested.path,$7)
LEFT JOIN cratectl.content_decisions d ON (d.tenant,d.repository,d.digest)=($5,$6,requested.digest)
LEFT JOIN cratectl.artifact_lifecycle l ON (l.tenant,l.repository,l.path)=($5,$6,requested.path)
LEFT JOIN cratectl.retrievals cached ON (cached.tenant,cached.repository,cached.path,cached.source_revision)=($5,$6,requested.path,$7)
WHERE NOT COALESCE(l.deleted,false) AND COALESCE(d.decision,a.decision,'unassessed')<>'denied'
 AND NOT COALESCE(cached.state IN ('negative','failed') AND cached.fresh_until>clock_timestamp(),false)
 AND (a.path IS NULL OR (a.digest=requested.digest AND a.metadata->>'archive_validated'='true' AND a.metadata->>'md5'=requested.md5
   AND ((a.metadata->'description')-'Title'::text-'Description'::text)=(requested.description::jsonb-'Title'::text-'Description'::text)))
 AND (NOT $8::boolean OR (COALESCE(d.decision,a.decision)='allowed' AND a.path IS NOT NULL AND
   cached.state='ready' AND cached.fresh_until>clock_timestamp()))
ORDER BY requested.position`, paths, digests, requirements, md5s, i.Tenant, current.Name, current.SourceRevision, current.RequireReview)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var position int
			if err := rows.Scan(&position); err != nil {
				return err
			}
			if position < 1 || position > len(files) {
				return ErrConflict
			}
			entry := catalog[files[position-1]]
			line := entry.Description.IndexEntry(entry.MD5, entry.SHA256)
			if int64(output.Len()+len(line)) > byteLimit {
				return ErrMetadataLimit
			}
			output.WriteString(line)
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

func cranProxyBinding(ctx context.Context, tx pgx.Tx, repo Repository, path, expected string, admissions []NativeAdmission) (cran.CatalogEntry, error) {
	coordinate, digest, valid := cran.ParsePinnedSourcePath(path)
	if !valid {
		return cran.CatalogEntry{}, ErrNotFound
	}
	if err := notDeletedInTx(ctx, tx, repo.Name, path); err != nil {
		return cran.CatalogEntry{}, err
	}
	var denied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.content_decisions WHERE repository=$1 AND digest=$2 AND decision='denied')`,
		repo.Name, digest).Scan(&denied); err != nil {
		return cran.CatalogEntry{}, err
	}
	if denied {
		return cran.CatalogEntry{}, ErrDenied
	}
	if err := checkCRANProxyGeneration(ctx, tx, repo, CRANProxyCatalogPath, admissions); err != nil {
		return cran.CatalogEntry{}, err
	}
	var current string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT a.digest,
 CASE WHEN octet_length((a.metadata->$4::text)::text)<=$5 THEN a.metadata->$4::text ELSE NULL END
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.repository=$1 AND a.path=$2 AND a.source_revision=$3 AND a.media_type=$6
 AND NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision)<>'denied'`,
		repo.Name, CRANProxyCatalogPath, repo.SourceRevision, coordinate.Path(), cranMetadataLimit, CRANProxyCatalogMedia).Scan(&current, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return cran.CatalogEntry{}, ErrSourceChanged
	}
	if err != nil {
		return cran.CatalogEntry{}, err
	}
	if current != expected {
		return cran.CatalogEntry{}, ErrSourceChanged
	}
	if len(raw) == 0 {
		return cran.CatalogEntry{}, ErrNotFound
	}
	var entry cran.CatalogEntry
	if json.Unmarshal(raw, &entry) != nil || entry.Coordinate() != coordinate || !entry.Valid() || entry.SHA256 != digest {
		return cran.CatalogEntry{}, ErrConflict
	}
	return entry, nil
}

func (s *Store) CRANProxyBinding(ctx context.Context, i Identity, repo Repository, path, expected string, admissions []NativeAdmission) (cran.CatalogEntry, error) {
	var entry cran.CatalogEntry
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		current, err := checkCRANProxySource(ctx, tx, i, repo)
		if err != nil {
			return err
		}
		entry, err = cranProxyBinding(ctx, tx, current, path, expected, admissions)
		return err
	})
	return entry, err
}

func (s *Store) CRANProxyArtifact(ctx context.Context, i Identity, repo Repository, path, expected string, admissions []NativeAdmission) (Artifact, error) {
	var a Artifact
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		current, err := checkCRANProxySource(ctx, tx, i, repo)
		if err != nil {
			return err
		}
		if err := checkCRANProxyGeneration(ctx, tx, current, path, admissions); err != nil {
			return err
		}
		budget := repositoryReadBudget(current)
		budget.sqlMetadataBytes = cranMetadataLimit
		a, err = readArtifact(ctx, tx, current.Name, path, current.RequireReview, budget)
		if err != nil {
			return err
		}
		packageInfo, err := validateCRANProxyArchive(a)
		if err != nil || expected == "" {
			return err
		}
		entry, err := cranProxyBinding(ctx, tx, current, path, expected, admissions)
		if err != nil {
			return err
		}
		if !entry.Matches(packageInfo.Description, packageInfo.MD5) {
			return ErrConflict
		}
		return nil
	})
	return a, err
}

type CRANProxyAdmission struct {
	CatalogDigest string
	Generations   []NativeAdmission
}

func validateCRANRetrieval(ctx context.Context, tx pgx.Tx, repo Repository, lease Retrieval, result RetrievalResult) error {
	if result.Failure != "" || result.Status != 200 && result.Status != 304 {
		return nil
	}
	if lease.Path == CRANProxyCatalogPath {
		if result.Status == 304 {
			return nil
		}
		if result.Object == nil || result.Object.Size != int64(len(result.Metadata)) || crypt.Digest(result.Metadata) != result.Object.Digest {
			return ErrConflict
		}
		a := Artifact{Path: lease.Path, MediaType: result.MediaType, Digest: result.Object.Digest, Metadata: result.Metadata}
		_, err := decodeCRANProxyCatalog(a, 10000, cran.MaxCatalogBytes)
		return err
	}
	if result.CRANProxy == nil || !uploadDigest.MatchString(result.CRANProxy.CatalogDigest) {
		return ErrConflict
	}
	entry, err := cranProxyBinding(ctx, tx, repo, lease.Path, result.CRANProxy.CatalogDigest, result.CRANProxy.Generations)
	if err != nil || result.Status == 304 {
		return err
	}
	if result.Object == nil {
		return ErrConflict
	}
	a := Artifact{Path: lease.Path, MediaType: result.MediaType, Digest: result.Object.Digest, Size: result.Object.Size, Metadata: result.Metadata}
	packageInfo, err := validateCRANProxyArchive(a)
	if err != nil || !entry.Matches(packageInfo.Description, packageInfo.MD5) {
		return ErrConflict
	}
	return nil
}
