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

const CargoCatalogMedia = "application/vnd.cratectl.cargo-proxy-catalog+json"

type CargoCatalog struct {
	Name    string              `json:"name"`
	Entries []cargo.SparseEntry `json:"entries"`
}

type CargoArchiveBinding struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	SourceKey     string `json:"source_key"`
	SourceURL     string `json:"source_url"`
	Checksum      string `json:"checksum"`
	CatalogDigest string `json:"-"`
}

func CargoCatalogPath(name string) string { return "cargo-catalog/" + name }

func CargoProxyPath(name, version string) (string, error) {
	nameKey, e := cargo.NameKey(name)
	if e != nil {
		return "", e
	}
	versionKey, e := cargo.VersionKey(version)
	if e != nil {
		return "", e
	}
	return "crates/" + nameKey + "/" + versionKey + ".crate", nil
}

func CargoSourceKey(name, version string) string {
	path, _ := CargoProxyPath(name, version)
	return crypt.Digest([]byte("cargo\x00" + path))
}

// CargoCanonicalSource strips mutable index annotations from the immutable
// descriptor. A yank or publication-time correction retains the same pin.
func CargoCanonicalSource(entry cargo.SparseEntry) ([]byte, error) {
	entry.Yanked, entry.Published = false, ""
	return json.Marshal(entry)
}

func cargoProxyRepository(ctx context.Context, tx pgx.Tx, i Identity, name string, revision int64) (Repository, error) {
	r, err := repositoryInTx(ctx, tx, i, name, "read")
	if err != nil {
		return r, err
	}
	if r.Mode != "proxy" || r.Format != "cargo" {
		return r, ErrConflict
	}
	if r.SourceRevision != revision {
		return r, ErrSourceChanged
	}
	return r, nil
}

func cargoCatalogInTx(ctx context.Context, tx pgx.Tx, repo Repository, name string) (Artifact, CargoCatalog, error) {
	var catalog CargoCatalog
	budget := repositoryReadBudget(repo)
	budget.sqlMetadataBytes = 32 << 20
	a, err := readArtifact(ctx, tx, repo.Name, CargoCatalogPath(name), false, budget)
	if err != nil {
		return a, catalog, err
	}
	if a.MediaType != CargoCatalogMedia || json.Unmarshal(a.Metadata, &catalog) != nil ||
		catalog.Name != name || len(catalog.Entries) == 0 || len(catalog.Entries) > 10000 {
		return a, catalog, ErrCargoUnvalidated
	}
	return a, catalog, nil
}

func cargoCacheInTx(ctx context.Context, tx pgx.Tx, repo Repository, path string, admissions []NativeAdmission) error {
	var state Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo.Name, path), &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	if state.SourceRevision != repo.SourceRevision {
		return ErrSourceChanged
	}
	if state.State == "negative" {
		return ErrNotFound
	}
	if state.State == "ready" && state.Fresh() {
		return nil
	}
	if state.State == "ready" || (state.State == "failed" && state.StalePermitted()) {
		admitted, e := ociCacheAdmission(ctx, tx, repo.Name, state, admissions)
		if e != nil {
			return e
		}
		if admitted {
			return nil
		}
	}
	return ErrBusy
}

// CargoProxyIndex rebuilds the advertised rows from one current snapshot of
// the pin and local byte policy. Pending index metadata cannot approve a crate.
func (s *Store) CargoProxyIndex(ctx context.Context, i Identity, repo, name string, revision int64, expectedDigest string, limit int, budget int64, admissions ...NativeAdmission) ([]byte, error) {
	var data []byte
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := cargoProxyRepository(ctx, tx, i, repo, revision)
		if e != nil {
			return e
		}
		if e = cargoCacheInTx(ctx, tx, r, CargoCatalogPath(name), admissions); e != nil {
			return e
		}
		a, catalog, e := cargoCatalogInTx(ctx, tx, r, name)
		if e != nil {
			return e
		}
		if a.Digest != expectedDigest {
			return ErrSourceChanged
		}
		if len(catalog.Entries) > limit || int64(len(a.Metadata)) > budget {
			return ErrMetadataLimit
		}
		paths, digests := make([]string, 0, len(catalog.Entries)), make([]string, 0, len(catalog.Entries))
		for _, row := range catalog.Entries {
			p, e := CargoProxyPath(row.Name, row.Version)
			if e != nil || !strings.EqualFold(row.Name, name) || !cargoDigest.MatchString(row.Checksum) {
				return ErrCargoUnvalidated
			}
			paths, digests = append(paths, p), append(digests, row.Checksum)
		}
		rows, e := tx.Query(ctx, `SELECT p.position FROM unnest($1::text[],$2::text[]) WITH ORDINALITY AS p(path,digest,position)
LEFT JOIN cratectl.artifacts a ON (a.repository,a.path,a.source_revision,a.digest)=($3,p.path,$4,p.digest)
LEFT JOIN cratectl.content_decisions d ON (d.repository,d.digest)=($3,p.digest)
LEFT JOIN cratectl.artifact_lifecycle nl ON (nl.repository,nl.path)=($3,p.path)
WHERE NOT COALESCE(nl.deleted,false) AND COALESCE(d.decision,a.decision,'unassessed')<>'denied'
AND (NOT $5::boolean OR (a.media_type=$6 AND COALESCE(d.decision,a.decision)='allowed'))
ORDER BY p.position LIMIT $7`, paths, digests, repo, revision, r.RequireReview, cargo.MediaType, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var n int
			if e = rows.Scan(&n); e != nil {
				return e
			}
			if n < 1 || n > len(catalog.Entries) {
				return ErrCargoUnvalidated
			}
			row, e := json.Marshal(catalog.Entries[n-1])
			if e != nil {
				return e
			}
			if int64(len(data)+len(row)+1) > budget {
				return ErrMetadataLimit
			}
			data = append(append(data, row...), '\n')
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNotFound
	}
	return data, nil
}

// The current index chooses a version and the immutable descriptor supplies its
// exact source URL. Retained descriptors alone cannot authorize a download.
func cargoArchiveBindingInTx(ctx context.Context, tx pgx.Tx, r Repository, name, version string) (CargoArchiveBinding, json.RawMessage, error) {
	var binding CargoArchiveBinding
	versionKey, e := cargo.VersionKey(version)
	if e != nil {
		return binding, nil, ErrNotFound
	}
	a, catalog, e := cargoCatalogInTx(ctx, tx, r, name)
	if e != nil {
		return binding, nil, e
	}
	for _, entry := range catalog.Entries {
		keyVersion, e := cargo.VersionKey(entry.Version)
		if e != nil {
			return binding, nil, ErrCargoUnvalidated
		}
		if keyVersion != versionKey {
			continue
		}
		key := CargoSourceKey(name, version)
		source, e := nativeSource(ctx, tx, r.Name, key, "cargo")
		if e != nil {
			return binding, nil, e
		}
		if !strings.EqualFold(entry.Name, name) || source.Name != name || source.Version != entry.Version || source.Coordinate != versionKey ||
			source.Integrity != "sha256:"+entry.Checksum || !cargoDigest.MatchString(entry.Checksum) {
			return binding, nil, ErrCargoUnvalidated
		}
		return CargoArchiveBinding{entry.Name, entry.Version, key, source.URL, entry.Checksum, a.Digest}, source.Metadata, nil
	}
	return binding, nil, ErrNotFound
}

func (s *Store) CargoProxyBinding(ctx context.Context, i Identity, repo, name, version string, revision int64) (CargoArchiveBinding, json.RawMessage, error) {
	var binding CargoArchiveBinding
	var metadata json.RawMessage
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := cargoProxyRepository(ctx, tx, i, repo, revision)
		if e != nil {
			return e
		}
		binding, metadata, e = cargoArchiveBindingInTx(ctx, tx, r, name, version)
		return e
	})
	return binding, metadata, e
}

func (s *Store) CargoProxyDownload(ctx context.Context, i Identity, repo, name, version string, revision int64, expected CargoArchiveBinding, admissions ...NativeAdmission) (Artifact, error) {
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := cargoProxyRepository(ctx, tx, i, repo, revision)
		if e != nil {
			return e
		}
		if e = cargoCacheInTx(ctx, tx, r, CargoCatalogPath(name), admissions); e != nil {
			return e
		}
		binding, _, e := cargoArchiveBindingInTx(ctx, tx, r, name, version)
		if e != nil {
			return e
		}
		if expected != binding || binding.Version != version {
			return ErrSourceChanged
		}
		p, e := CargoProxyPath(name, version)
		if e != nil {
			return ErrCargoUnvalidated
		}
		if e = cargoCacheInTx(ctx, tx, r, p, admissions); e != nil {
			return e
		}
		a, e = readArtifact(ctx, tx, repo, p, r.RequireReview, repositoryReadBudget(r))
		if e != nil {
			return e
		}
		if !validCargoArchive(a, binding) {
			return ErrCargoUnvalidated
		}
		return nil
	})
	return a, e
}

func validCargoArchive(a Artifact, binding CargoArchiveBinding) bool {
	var saved CargoArchiveBinding
	binding.CatalogDigest = ""
	return a.Digest == binding.Checksum && a.MediaType == cargo.MediaType && a.Size > 0 && a.Size <= cargo.MaxUploadBytes &&
		json.Unmarshal(a.Metadata, &saved) == nil && saved == binding
}
