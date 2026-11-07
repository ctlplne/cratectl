// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrBusy = errors.New("retrieval already running")
var ErrLeaseLost = errors.New("retrieval lease expired or was superseded")

type Retrieval struct {
	SourceRevision       int64     `json:"source_revision"`
	SourceChanged        bool      `json:"source_changed"`
	Repository           string    `json:"repository"`
	Path                 string    `json:"path"`
	Generation           int64     `json:"generation"`
	Token                string    `json:"-"`
	LeaseUntil           time.Time `json:"lease_until"`
	State                string    `json:"state"`
	FreshUntil           time.Time `json:"fresh_until"`
	StaleUntil           time.Time `json:"stale_until"`
	ETag                 string    `json:"-"`
	Modified             string    `json:"-"`
	LastStatus           int       `json:"last_status"`
	LastError            string    `json:"last_error"`
	Now                  time.Time `json:"observed_at"`
	SourceFresh          int       `json:"-"`
	SourceStale          int       `json:"-"`
	Acquired             bool      `json:"-"`
	ChangedAt            time.Time `json:"changed_at"`
	ChangeSequence       int64     `json:"change_sequence"`
	ValidationRoot       string    `json:"validation_root,omitempty"`
	ValidationGeneration int64     `json:"validation_generation,omitempty"`
}

func (r Retrieval) Fresh() bool { return !r.SourceChanged && r.FreshUntil.After(r.Now) }
func (r Retrieval) StalePermitted() bool {
	return !r.SourceChanged && r.StaleUntil.After(r.Now) && r.LastError == "transient_upstream_failure"
}

const retrievalColumns = `repository,path,generation,lease_token,lease_until,state,fresh_until,stale_until,etag,modified,last_status,last_error,source_fresh_seconds,source_stale_seconds,clock_timestamp(),changed_at,validation_root,validation_generation,change_sequence,source_revision`

func scanRetrieval(row pgx.Row, r *Retrieval) error {
	return row.Scan(&r.Repository, &r.Path, &r.Generation, &r.Token, &r.LeaseUntil, &r.State, &r.FreshUntil, &r.StaleUntil, &r.ETag, &r.Modified, &r.LastStatus, &r.LastError, &r.SourceFresh, &r.SourceStale, &r.Now, &r.ChangedAt, &r.ValidationRoot, &r.ValidationGeneration, &r.ChangeSequence, &r.SourceRevision)
}
func (s *Store) Retrieval(ctx context.Context, i Identity, repo, path string, expected ...int64) (Retrieval, error) {
	var r Retrieval
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		cfg, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if cfg.Mode != "proxy" {
			return ErrConflict
		}
		if len(expected) > 0 && cfg.SourceRevision != expected[0] {
			return ErrSourceChanged
		}
		e = scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo, path), &r)
		r.SourceChanged = r.SourceRevision != cfg.SourceRevision
		return e
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	return r, e
}
func (s *Store) AcquireRetrieval(ctx context.Context, i Identity, repo, path, token string, force bool, limits ...int) (Retrieval, error) {
	limit := 32
	if len(limits) > 0 {
		limit = limits[0]
	}
	return s.AcquireRetrievalWithLease(ctx, i, repo, path, token, force, limit, 150*time.Second)
}
func (s *Store) AcquireRetrievalWithLease(ctx context.Context, i Identity, repo, path, token string, force bool, limit int, lease time.Duration, expected ...int64) (Retrieval, error) {
	return s.acquireRetrievalWithLease(ctx, i, repo, path, token, force, limit, lease, expected, 0)
}

// AcquireRetrievalRefresh forces only the generation whose proof was observed
// expired. If another caller already refreshed it, return the current state for
// re-evaluation instead of starting a second forced fill from a stale observation.
func (s *Store) AcquireRetrievalRefresh(ctx context.Context, i Identity, observed Retrieval, token string, limit int, lease time.Duration) (Retrieval, error) {
	if observed.Generation <= 0 || observed.SourceRevision < 0 {
		return Retrieval{}, ErrConflict
	}
	return s.acquireRetrievalWithLease(ctx, i, observed.Repository, observed.Path, token, true, limit, lease, []int64{observed.SourceRevision}, observed.Generation)
}

func (s *Store) acquireRetrievalWithLease(ctx context.Context, i Identity, repo, path, token string, force bool, limit int, lease time.Duration, expected []int64, generation int64) (Retrieval, error) {
	if limit <= 0 || lease < time.Second || lease > 5*time.Minute || token == "" {
		return Retrieval{}, ErrConflict
	}
	r := Retrieval{Repository: repo, Path: path}
	e := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		cfg, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if cfg.Mode != "proxy" {
			return ErrConflict
		}
		if len(expected) > 0 && cfg.SourceRevision != expected[0] {
			return ErrSourceChanged
		}
		if e := goChecksumRepositoryUsable(ctx, tx, cfg); e != nil {
			return e
		}
		if e = notDeletedInTx(ctx, tx, repo, path); e != nil {
			return e
		}
		e = scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2 FOR UPDATE`, repo, path), &r)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil && r.SourceRevision == cfg.SourceRevision {
			if generation > 0 && r.Generation != generation {
				return nil
			}
			if r.State == "fetching" && r.LeaseUntil.After(r.Now) {
				return ErrBusy
			}
			if !force && r.State != "fetching" && r.Fresh() {
				return nil
			}
		}
		var n int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.retrievals WHERE state='fetching' AND lease_until>clock_timestamp()`).Scan(&n); e != nil {
			return e
		}
		if n >= limit {
			return ErrBusy
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return e
		}
		r.Generation++
		r.Token = token
		e = scanRetrieval(tx.QueryRow(ctx, `INSERT INTO cratectl.retrievals(tenant,repository,path,generation,lease_token,lease_until,state,change_sequence,source_revision) VALUES($1,$2,$3,$4,$5,clock_timestamp()+make_interval(secs=>$7),'fetching',$6,$8) ON CONFLICT(tenant,repository,path) DO UPDATE SET generation=excluded.generation,lease_token=excluded.lease_token,lease_until=excluded.lease_until,state='fetching',changed_at=clock_timestamp(),change_sequence=excluded.change_sequence,etag=CASE WHEN cratectl.retrievals.source_revision<>excluded.source_revision THEN '' ELSE cratectl.retrievals.etag END,modified=CASE WHEN cratectl.retrievals.source_revision<>excluded.source_revision THEN '' ELSE cratectl.retrievals.modified END,fresh_until=CASE WHEN cratectl.retrievals.source_revision<>excluded.source_revision THEN 'epoch'::timestamptz ELSE cratectl.retrievals.fresh_until END,stale_until=CASE WHEN cratectl.retrievals.source_revision<>excluded.source_revision THEN 'epoch'::timestamptz ELSE cratectl.retrievals.stale_until END,source_fresh_seconds=CASE WHEN cratectl.retrievals.source_revision<>excluded.source_revision THEN 0 ELSE cratectl.retrievals.source_fresh_seconds END,source_stale_seconds=CASE WHEN cratectl.retrievals.source_revision<>excluded.source_revision THEN 0 ELSE cratectl.retrievals.source_stale_seconds END,source_revision=excluded.source_revision RETURNING `+retrievalColumns, i.Tenant, repo, path, r.Generation, token, sequence, lease.Seconds(), cfg.SourceRevision), &r)
		if e != nil {
			return e
		}
		r.Acquired = true
		return appendEvent(ctx, tx, i, "proxy.retrieval.started", map[string]any{"repository": repo, "path": path, "generation": r.Generation, "source_revision": r.SourceRevision})
	})
	return r, e
}

func (s *Store) RenewRetrieval(ctx context.Context, i Identity, r Retrieval, lease time.Duration) error {
	if lease < time.Second || lease > 5*time.Minute {
		return ErrConflict
	}
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		config, e := repositoryInTx(ctx, tx, i, r.Repository, "read")
		if e != nil {
			return e
		}
		if config.SourceRevision != r.SourceRevision {
			return ErrSourceChanged
		}
		if e := goChecksumRepositoryUsable(ctx, tx, config); e != nil {
			return e
		}
		var state string
		var valid bool
		e = tx.QueryRow(ctx, `SELECT state,lease_until>clock_timestamp() FROM cratectl.retrievals WHERE repository=$1 AND path=$2 AND generation=$3 AND lease_token=$4 AND source_revision=$5 FOR UPDATE`, r.Repository, r.Path, r.Generation, r.Token, r.SourceRevision).Scan(&state, &valid)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrLeaseLost
		}
		if e != nil {
			return e
		}
		// A heartbeat racing its own completion has no further lease to extend.
		if state != "fetching" {
			return nil
		}
		if !valid {
			return ErrLeaseLost
		}
		if e = notDeletedInTx(ctx, tx, r.Repository, r.Path); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until=clock_timestamp()+make_interval(secs=>$1) WHERE repository=$2 AND path=$3 AND lease_until>clock_timestamp()`, lease.Seconds(), r.Repository, r.Path)
		if e == nil && tag.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		return e
	})
}

type RetrievalResult struct {
	Status                     int
	Object                     *blob.Object
	Metadata                   []byte
	ETag, Modified, Failure    string
	FreshSeconds, StaleSeconds int
	MediaType                  string
	NPMCatalog                 *NPMCatalog
	NPMSources                 []NPMSource
	NativeCatalog              *NativeCatalogPublication
	OCI                        *OCIPublication
	GoModule                   *GoModulePublication
	GoCatalog                  *GoModuleCatalog
	GoLatest                   *GoModuleLatest
	GoChecksumFailure          *GoChecksumFailure
}

func (s *Store) CompleteRetrieval(ctx context.Context, i Identity, lease Retrieval, result RetrievalResult) error {
	var rejectedPublication error
	e := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		repo, e := repositoryInTx(ctx, tx, i, lease.Repository, "read")
		if e != nil {
			return e
		}
		if repo.Mode != "proxy" {
			return ErrConflict
		}
		if repo.SourceRevision != lease.SourceRevision {
			return ErrSourceChanged
		}
		var valid bool
		e = tx.QueryRow(ctx, `SELECT generation=$1 AND lease_token=$2 AND state='fetching' AND lease_until>clock_timestamp() AND source_revision=$5 FROM cratectl.retrievals WHERE repository=$3 AND path=$4 FOR UPDATE`, lease.Generation, lease.Token, lease.Repository, lease.Path, lease.SourceRevision).Scan(&valid)
		if e != nil {
			return e
		}
		if !valid {
			return ErrLeaseLost
		}
		if result.GoCatalog != nil {
			if e = validateGoModuleCatalogRetrieval(repo, lease, result); e != nil {
				return e
			}
		}
		if result.GoLatest != nil {
			if e = validateGoModuleLatestRetrieval(repo, lease, result); e != nil {
				return e
			}
		}
		if result.GoModule != nil || repo.Format == "go" && result.GoCatalog == nil && result.GoLatest == nil && (result.Status == 200 || result.Status == 304) && result.Failure == "" {
			if e = validateGoModuleRetrieval(repo, lease, result); e != nil {
				return e
			}
		}
		if e = notDeletedInTx(ctx, tx, lease.Repository, lease.Path); e != nil {
			return e
		}
		if result.Status == 304 && result.Failure == "" {
			var bound bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2 AND source_revision=$3)`, lease.Repository, lease.Path, lease.SourceRevision).Scan(&bound); e != nil {
				return e
			}
			if !bound {
				return ErrSourceRevalidation
			}
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return e
		}
		failureDigest := ""
		if result.GoModule != nil && result.GoModule.Checksum != nil && result.Failure == "" {
			failure, err := proposedGoChecksumFork(ctx, tx, repo, result.GoModule.Checksum)
			if err != nil {
				return err
			}
			if failure != nil {
				result = RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: failure}
				rejectedPublication = crypt.ErrGoChecksumFork
			}
		}
		if result.GoChecksumFailure != nil {
			if result.GoModule != nil || result.Object != nil || result.GoCatalog != nil || result.GoLatest != nil || result.Failure == "" {
				return ErrGoModuleUnvalidated
			}
			classification, digest, err := completeGoChecksumFailure(ctx, tx, i, repo, lease, *result.GoChecksumFailure, sequence)
			if err != nil {
				return err
			}
			cancelled := result.Failure == "retrieval_cancelled"
			result.Failure = "upstream_checksum_unverified"
			if classification == "fork" {
				result.Failure = "upstream_checksum_fork"
			} else if cancelled {
				result.Failure = "retrieval_cancelled"
			}
			result.Status = 0
			failureDigest = digest
		}
		state := "ready"
		var replacement *referenceReplacement
		fresh := result.FreshSeconds
		stale := result.StaleSeconds
		if (result.Status == 200 || (result.Status == 304 && result.OCI != nil)) && result.Failure == "" {
			if repo.Format == "oci" && result.OCI == nil {
				return ErrConflict
			}
			if result.Object == nil {
				return errors.New("durable object required")
			}
			if len(result.Metadata) == 0 {
				result.Metadata = []byte(`{}`)
			}
			if result.OCI != nil {
				if strings.HasPrefix(lease.Path, "oci-catalog/") {
					var c OCICatalog
					if result.MediaType != OCICatalogMedia || json.Unmarshal(result.Metadata, &c) != nil || c.Image != result.OCI.Image || crypt.Digest(result.Metadata) != result.Object.Digest {
						return ErrConflict
					}
				}
				if e = completeOCIPublication(ctx, tx, i, repo, lease, *result.OCI, result.Object.Digest, result.Object.Size, result.FreshSeconds, result.StaleSeconds, sequence); e != nil {
					return e
				}
			}
			if result.GoModule != nil {
				if e = completeGoModulePublication(ctx, tx, i, repo, lease, result, sequence); e != nil {
					return e
				}
			}
			publication := result.NativeCatalog
			if result.NPMCatalog != nil {
				if repo.Format != "npm" || lease.Path != NPMCatalogPath(result.NPMCatalog.Name) || len(result.NPMSources) != len(result.NPMCatalog.Versions) {
					return ErrConflict
				}
				publication = &NativeCatalogPublication{Name: result.NPMCatalog.Name, Entries: result.NPMCatalog.Versions}
				for _, source := range result.NPMSources {
					publication.Sources = append(publication.Sources, NativeSource{Key: source.Key, Format: "npm", Name: source.Name, Coordinate: source.Version, Version: source.Version, URL: source.Tarball, Integrity: source.Integrity, Metadata: source.Package})
				}
			}
			if publication != nil {
				if (repo.Format != "npm" && repo.Format != "pypi") || lease.Path != repo.Format+"-catalog/"+publication.Name || len(publication.Entries) != len(publication.Sources) {
					return ErrConflict
				}
				seen := map[string]bool{}
				for _, source := range publication.Sources {
					if seen[source.Coordinate] || source.Format != repo.Format || source.Name != publication.Name || publication.Entries[source.Coordinate] != source.Key {
						return ErrConflict
					}
					seen[source.Coordinate] = true
					_, e = tx.Exec(ctx, `INSERT INTO cratectl.native_sources(tenant,repository,key,format,package,coordinate,version,url,integrity,metadata,source_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`, i.Tenant, repo.Name, source.Key, source.Format, source.Name, source.Coordinate, source.Version, source.URL, source.Integrity, source.Metadata, lease.SourceRevision)
					if e != nil {
						return e
					}
				}
			}
			media := result.MediaType
			if media == "" {
				media = "application/octet-stream"
			}
			replacement, e = prepareReferenceReplacement(ctx, tx, i, lease.Repository, lease.Path, result.Object.Digest, sequence)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,source_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant,repository,path) DO UPDATE SET digest=excluded.digest,size=excluded.size,media_type=excluded.media_type,metadata=excluded.metadata,source_revision=excluded.source_revision,decision=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.decision ELSE 'unassessed' END,created_at=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.created_at ELSE now() END`, i.Tenant, lease.Repository, lease.Path, result.Object.Digest, result.Object.Size, media, result.Metadata, lease.SourceRevision)
			if e != nil {
				return e
			}
			if e = enqueueIntegrity(ctx, tx, i, repo.Name, []Artifact{{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size}}); e != nil {
				return e
			}
		} else if result.Status == 304 && result.Failure == "" {
			var exists bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, lease.Repository, lease.Path).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				return ErrConflict
			}
		} else if result.Status == 404 && result.Failure == "" {
			state = "negative"
			fresh = result.FreshSeconds
			stale = 0
			if repo.Format == "oci" {
				if n := strings.LastIndex(lease.Path, "/manifests/"); n > 0 {
					ref := lease.Path[n+len("/manifests/"):]
					if !strings.HasPrefix(ref, "sha256:") {
						var newer bool
						if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.tags WHERE repository=$1 AND image=$2 AND tag=$3 AND change_sequence>$4)`, repo.Name, lease.Path[:n], ref, lease.ChangeSequence).Scan(&newer); e != nil {
							return e
						}
						if newer {
							return ErrOCIMemberChanged
						}
						if _, e = tx.Exec(ctx, `UPDATE cratectl.tags SET deleted=true,version=version+1,changed_at=clock_timestamp(),change_sequence=$4,source_revision=$5 WHERE repository=$1 AND image=$2 AND tag=$3`, repo.Name, lease.Path[:n], ref, sequence, lease.SourceRevision); e != nil {
							return e
						}
					}
				}
			}
		} else {
			state = "failed"
			fresh = 2
			stale = -1
			if result.Failure == "" {
				return errors.New("failure classification required")
			}
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET state=$1,lease_until='epoch',fresh_until=now()+make_interval(secs=>$2),stale_until=CASE WHEN $3::int<0 THEN stale_until ELSE now()+make_interval(secs=>($2+$3)) END,etag=CASE WHEN $1='negative' THEN '' WHEN $1='ready' AND $6=200 THEN $4 WHEN $1='ready' AND $4<>'' THEN $4 ELSE etag END,modified=CASE WHEN $1='negative' THEN '' WHEN $1='ready' AND $6=200 THEN $5 WHEN $1='ready' AND $5<>'' THEN $5 ELSE modified END,last_status=$6,last_error=$7,source_fresh_seconds=CASE WHEN $1='ready' THEN $2 ELSE source_fresh_seconds END,source_stale_seconds=CASE WHEN $1='ready' THEN $3 ELSE source_stale_seconds END,changed_at=clock_timestamp(),change_sequence=$10,validation_root=CASE WHEN $1='ready' THEN path ELSE validation_root END,validation_generation=CASE WHEN $1='ready' THEN generation ELSE validation_generation END WHERE repository=$8 AND path=$9 AND state='fetching' AND generation=$11 AND lease_token=$12 AND lease_until>clock_timestamp()`, state, fresh, stale, result.ETag, result.Modified, result.Status, result.Failure, lease.Repository, lease.Path, sequence, lease.Generation, lease.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		data := map[string]any{"repository": lease.Repository, "path": lease.Path, "generation": lease.Generation, "state": state, "upstream_status": result.Status, "failure": result.Failure, "source_revision": lease.SourceRevision}
		if result.Object != nil {
			data["digest"] = result.Object.Digest
			data["size"] = result.Object.Size
		}
		if result.OCI != nil {
			data["graph_members"] = len(result.OCI.Objects)
			data["native_tags"] = len(result.OCI.Tags)
		}
		if result.GoModule != nil {
			data["go_module_representations"] = len(result.GoModule.Objects)
		}
		if result.GoCatalog != nil {
			data["go_module_catalog_versions"] = len(result.GoCatalog.Versions)
		}
		if result.GoLatest != nil {
			data["go_module_latest_version"] = result.GoLatest.Version
		}
		if replacement != nil {
			data["reference_replacement"] = replacement
		}
		if result.GoChecksumFailure != nil {
			data["go_checksum_failure_digest"] = failureDigest
			// Failure evidence and enforcement finish synchronously. No ordinary
			// queue capacity is required and no worker/delivery is promised.
			return appendEventIntent(ctx, tx, i, "proxy.retrieval."+state, data, false)
		}
		if repo.Format == "go" && result.Failure == "upstream_checksum_fork" {
			if err := appendEventIntent(ctx, tx, i, "proxy.retrieval."+state, data, false); err != nil {
				return err
			}
			return appendGoChecksumLegacyIncident(ctx, tx, i, sequence)
		}
		return appendEvent(ctx, tx, i, "proxy.retrieval."+state, data)
	})
	if e == nil && rejectedPublication != nil {
		return rejectedPublication
	}
	if e != nil && rejectedPublication != nil && result.GoChecksumFailure != nil {
		return &PendingGoChecksumFailure{failure: *result.GoChecksumFailure, cause: e}
	}
	if errors.Is(e, ErrQueueFull) {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if release := s.abandonQueueBlockedRetrieval(cleanup, i, lease); release != nil && !errors.Is(release, ErrLeaseLost) {
			return release
		}
	}
	if errors.Is(e, ErrHeld) {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if release := s.rejectHeldReplacement(cleanup, i, lease); release != nil && !errors.Is(release, ErrLeaseLost) {
			return release
		}
	}
	return e
}

// Reject a changed upstream object without stranding the fill lease. The prior
// validators and freshness deadlines stay unchanged: a hold never invents a
// successful upstream revalidation or permission to serve expired cached bytes.
func (s *Store) rejectHeldReplacement(ctx context.Context, i Identity, lease Retrieval) error {
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, lease.Repository, "read")
		if e != nil {
			return e
		}
		if r.SourceRevision != lease.SourceRevision {
			return ErrLeaseLost
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET state='ready',lease_token='',lease_until='epoch',last_error='reference_held',changed_at=clock_timestamp(),change_sequence=$1 WHERE repository=$2 AND path=$3 AND generation=$4 AND lease_token=$5 AND state='fetching' AND lease_until>clock_timestamp()`, sequence, lease.Repository, lease.Path, lease.Generation, lease.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		return appendEventIntent(ctx, tx, i, "proxy.retrieval.rejected", map[string]any{"repository": lease.Repository, "path": lease.Path, "generation": lease.Generation, "reason": "reference_held", "source_revision": lease.SourceRevision}, false)
	})
}
func InvalidateRetrieval(ctx context.Context, tx pgx.Tx, i Identity, repo, path string) (any, error) {
	if i.Role != "admin" {
		return nil, ErrDenied
	}
	r, e := repositoryInTx(ctx, tx, i, repo, "read")
	if e != nil {
		return nil, e
	}
	if r.Mode != "proxy" {
		return nil, ErrConflict
	}
	sequence, e := nextEventSequence(ctx, tx, i)
	if e != nil {
		return nil, e
	}
	tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET generation=generation+1,lease_token='',lease_until='epoch',fresh_until='epoch',state=CASE WHEN state='fetching' THEN 'failed' ELSE state END,last_error='operator_revalidate',changed_at=clock_timestamp(),validation_root='',validation_generation=0,change_sequence=$3 WHERE repository=$1 AND path=$2`, repo, path, sequence)
	if e != nil {
		return nil, e
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return map[string]string{"repository": repo, "path": path, "state": "expired", "next_action": "Next authorized request retrieves or revalidates the configured upstream."}, nil
}

// Capacity rejection rolls back every publication reference. Release only this
// owner's still-live fence without requiring room in the already saturated
// outbox; the audit and failed lease update remain one local transaction.
func (s *Store) abandonQueueBlockedRetrieval(ctx context.Context, i Identity, lease Retrieval) error {
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		if _, e := repositoryInTx(ctx, tx, i, lease.Repository, "read"); e != nil {
			return e
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET state='failed',lease_token='',lease_until='epoch',fresh_until='epoch',last_error='queue_capacity',changed_at=clock_timestamp(),change_sequence=$1 WHERE repository=$2 AND path=$3 AND generation=$4 AND lease_token=$5 AND state='fetching' AND lease_until>clock_timestamp()`, sequence, lease.Repository, lease.Path, lease.Generation, lease.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		return appendEventIntent(ctx, tx, i, "proxy.retrieval.abandoned", map[string]any{"repository": lease.Repository, "path": lease.Path, "generation": lease.Generation, "reason": "queue_capacity"}, false)
	})
}
