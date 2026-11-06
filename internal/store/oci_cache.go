// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrOCICacheExpired = errors.New("OCI graph cache requires revalidation")
var ErrOCIMemberChanged = errors.New("OCI graph member changed during retrieval")

// Admission belongs to one request's just-completed fill. It permits a positive
// max-age=0 validation to admit that request, without making later requests fresh.
// Root generation/state and member validation receipts are rechecked in SQL.
type NativeAdmission struct {
	Repository, Path string
	Generation       int64
	Stale            bool
	GoChecksum       *GoChecksumAdmission `json:"-"`
}

type OCIAdmission = NativeAdmission
type NativeMemberCache struct {
	ETag, Modified             string
	FreshSeconds, StaleSeconds int
}

type OCIMemberCache = NativeMemberCache

func refreshNativeMember(ctx context.Context, tx pgx.Tx, i Identity, lease Retrieval, a Artifact, c NativeMemberCache, sequence int64) error {
	if a.Path == lease.Path {
		return nil
	}
	if c.FreshSeconds < 0 || c.FreshSeconds > 86400 || c.StaleSeconds < 0 || c.StaleSeconds > 604800 || len(c.ETag) > 1024 || len(c.Modified) > 128 {
		return ErrConflict
	}
	var current Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, lease.Repository, a.Path), &current)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if e == nil && current.SourceRevision == lease.SourceRevision {
		if current.State == "fetching" && current.LeaseUntil.After(current.Now) {
			return ErrOCIMemberChanged
		}
		if current.ChangeSequence > lease.ChangeSequence {
			if current.State == "ready" && current.Fresh() {
				return nil
			}
			return ErrOCIMemberChanged
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.retrievals(tenant,repository,path,generation,lease_token,lease_until,state,fresh_until,stale_until,etag,modified,last_status,last_error,source_fresh_seconds,source_stale_seconds,changed_at,validation_root,validation_generation,change_sequence,source_revision)
 VALUES($1,$2,$3,1,'','epoch','ready',clock_timestamp()+make_interval(secs=>$4),clock_timestamp()+make_interval(secs=>($4+$5)),$6,$7,200,'',$4,$5,clock_timestamp(),$8,$9,$10,$11)
 ON CONFLICT(tenant,repository,path) DO UPDATE SET generation=cratectl.retrievals.generation+1,lease_token='',lease_until='epoch',state='ready',fresh_until=excluded.fresh_until,stale_until=excluded.stale_until,etag=excluded.etag,modified=excluded.modified,last_status=200,last_error='',source_fresh_seconds=excluded.source_fresh_seconds,source_stale_seconds=excluded.source_stale_seconds,changed_at=excluded.changed_at,validation_root=excluded.validation_root,validation_generation=excluded.validation_generation,change_sequence=excluded.change_sequence,source_revision=excluded.source_revision`, i.Tenant, lease.Repository, a.Path, c.FreshSeconds, c.StaleSeconds, c.ETag, c.Modified, lease.Path, lease.Generation, sequence, lease.SourceRevision)
	return e
}

func ociCacheAdmission(ctx context.Context, tx pgx.Tx, repo string, r Retrieval, admissions []OCIAdmission) (bool, error) {
	for _, a := range admissions {
		if a.Repository != repo {
			continue
		}
		var root Retrieval
		e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo, a.Path), &root)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return false, e
		}
		if root.Generation != a.Generation {
			continue
		}
		if a.Stale {
			memberStale := r.State == "ready" && r.LastError == "" && r.StaleUntil.After(r.Now)
			rootStale := r.Path == root.Path && r.Generation == root.Generation && r.StalePermitted()
			if root.State == "failed" && root.StalePermitted() && (memberStale || rootStale) {
				return true, nil
			}
		} else if root.State == "ready" && root.ValidationRoot == a.Path && root.ValidationGeneration == a.Generation && r.ValidationRoot == a.Path && r.ValidationGeneration == a.Generation && r.LastError == "" {
			return true, nil
		}
	}
	return false, nil
}

func ociGraphBudget(repo Repository, admissions []OCIAdmission) *graphBudget {
	b := newGraphBudget()
	if repo.Mode == "proxy" {
		b.cacheRepository = repo.Name
		b.sourceRevision = &repo.SourceRevision
		b.admissions = admissions
	}
	return b
}
