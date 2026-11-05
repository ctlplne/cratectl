// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

// GoModulePublication contains an already inspected and durably staged bundle.
// The common retrieval lease is always the canonical ZIP path, independent of
// which representation caused intake. Proxy HTTP mode remains disabled until
// its network/cache/current-policy path is implemented and qualified.
type GoModulePublication struct {
	Objects []Artifact
}

func validateGoModuleRetrieval(repo Repository, lease Retrieval, result RetrievalResult) error {
	if repo.Format != "go" || repo.Mode != "proxy" || lease.Repository != repo.Name || result.Status != 200 || result.Failure != "" || result.GoModule == nil || result.Object == nil || result.GoCatalog != nil || result.OCI != nil || result.NativeCatalog != nil || result.NPMCatalog != nil || len(result.NPMSources) != 0 {
		return ErrGoModuleUnvalidated
	}
	if result.FreshSeconds < 0 || result.FreshSeconds > 86400 || result.StaleSeconds < 0 || result.StaleSeconds > 604800 || len(result.ETag) > 1024 || len(result.Modified) > 128 || strings.ContainsAny(result.ETag+result.Modified, "\r\n\x00") {
		return ErrGoModuleUnvalidated
	}
	metadata, e := validateGoModuleBundle(result.GoModule.Objects)
	if e != nil {
		return e
	}
	coordinate, e := gomodule.Canonical(metadata.Module, metadata.Version)
	if e != nil || lease.Path != coordinate.Prefix()+".zip" {
		return ErrGoModuleUnvalidated
	}
	found := false
	for _, a := range result.GoModule.Objects {
		if a.Repository != "" && a.Repository != repo.Name {
			return ErrGoModuleUnvalidated
		}
		if e := (IntegrityTarget{Repository: repo.Name, Path: a.Path, Digest: a.Digest, Size: a.Size}).Validate(); e != nil {
			return ErrGoModuleUnvalidated
		}
		if a.Path == lease.Path {
			found = a.Digest == result.Object.Digest && a.Size == result.Object.Size && a.MediaType == result.MediaType && bytes.Equal(a.Metadata, result.Metadata)
		}
	}
	if !found {
		return ErrGoModuleUnvalidated
	}
	return nil
}

// CompleteRetrieval owns the surrounding current-authority/source/lease/event
// transaction. This helper adds the siblings and cache validation receipts to
// that transaction; any reference, integrity queue or final event failure rolls
// everything back. It never downloads bytes or marks absent scan evidence clean.
func completeGoModulePublication(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, lease Retrieval, result RetrievalResult, sequence int64) error {
	if e := validateGoModuleRetrieval(repo, lease, result); e != nil {
		return e
	}
	siblings := []Artifact{}
	for _, a := range result.GoModule.Objects {
		if e := notDeletedInTx(ctx, tx, repo.Name, a.Path); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,source_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, i.Tenant, repo.Name, a.Path, a.Digest, a.Size, a.MediaType, a.Metadata, lease.SourceRevision)
		if e != nil {
			return e
		}
		var digest, media string
		var size int64
		if e = tx.QueryRow(ctx, `SELECT digest,size,media_type FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo.Name, a.Path).Scan(&digest, &size, &media); e != nil {
			return e
		}
		// This first intake profile is immutable across all three representations,
		// including info. A source switch cannot silently rewrite an old version.
		if digest != a.Digest || size != a.Size || media != a.MediaType {
			return ErrConflict
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=$1,source_revision=$2 WHERE repository=$3 AND path=$4`, a.Metadata, lease.SourceRevision, repo.Name, a.Path); e != nil {
			return e
		}
		if a.Path != lease.Path {
			siblings = append(siblings, a)
		}
		cache := NativeMemberCache{FreshSeconds: result.FreshSeconds, StaleSeconds: result.StaleSeconds}
		if e = refreshNativeMember(ctx, tx, i, lease, a, cache, sequence); e != nil {
			return e
		}
	}
	// The common completion path enqueues the ZIP root once after this helper.
	return enqueueIntegrity(ctx, tx, i, repo.Name, siblings)
}
