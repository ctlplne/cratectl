// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"github.com/jackc/pgx/v5"
)

var ErrBusy = errors.New("retrieval already running")
var ErrLeaseLost = errors.New("retrieval lease expired or was superseded")

type Retrieval struct {
	Repository  string    `json:"repository"`
	Path        string    `json:"path"`
	Generation  int64     `json:"generation"`
	Token       string    `json:"-"`
	LeaseUntil  time.Time `json:"lease_until"`
	State       string    `json:"state"`
	FreshUntil  time.Time `json:"fresh_until"`
	StaleUntil  time.Time `json:"stale_until"`
	ETag        string    `json:"-"`
	Modified    string    `json:"-"`
	LastStatus  int       `json:"last_status"`
	LastError   string    `json:"last_error"`
	Now         time.Time `json:"observed_at"`
	SourceFresh int       `json:"-"`
	SourceStale int       `json:"-"`
	Acquired    bool      `json:"-"`
}

func (r Retrieval) Fresh() bool { return r.FreshUntil.After(r.Now) }
func (r Retrieval) StalePermitted() bool {
	return r.StaleUntil.After(r.Now) && r.LastError == "transient_upstream_failure"
}

const retrievalColumns = `repository,path,generation,lease_token,lease_until,state,fresh_until,stale_until,etag,modified,last_status,last_error,source_fresh_seconds,source_stale_seconds,clock_timestamp()`

func scanRetrieval(row pgx.Row, r *Retrieval) error {
	return row.Scan(&r.Repository, &r.Path, &r.Generation, &r.Token, &r.LeaseUntil, &r.State, &r.FreshUntil, &r.StaleUntil, &r.ETag, &r.Modified, &r.LastStatus, &r.LastError, &r.SourceFresh, &r.SourceStale, &r.Now)
}
func (s *Store) Retrieval(ctx context.Context, i Identity, repo, path string) (Retrieval, error) {
	var r Retrieval
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		cfg, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if cfg.Mode != "proxy" {
			return ErrConflict
		}
		return scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo, path), &r)
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
	if limit <= 0 {
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
		e = scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2 FOR UPDATE`, repo, path), &r)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil {
			if r.State == "fetching" && r.LeaseUntil.After(r.Now) {
				return ErrBusy
			}
			if !force && r.State != "fetching" && r.Fresh() {
				return nil
			}
		}
		var n int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.retrievals WHERE state='fetching' AND lease_until>now()`).Scan(&n); e != nil {
			return e
		}
		if n >= limit {
			return ErrBusy
		}
		r.Generation++
		r.Token = token
		e = scanRetrieval(tx.QueryRow(ctx, `INSERT INTO cratectl.retrievals(tenant,repository,path,generation,lease_token,lease_until,state) VALUES($1,$2,$3,$4,$5,now()+interval '150 seconds','fetching') ON CONFLICT(tenant,repository,path) DO UPDATE SET generation=excluded.generation,lease_token=excluded.lease_token,lease_until=excluded.lease_until,state='fetching' RETURNING `+retrievalColumns, i.Tenant, repo, path, r.Generation, token), &r)
		if e != nil {
			return e
		}
		r.Acquired = true
		return appendEvent(ctx, tx, i, "proxy.retrieval.started", map[string]any{"repository": repo, "path": path, "generation": r.Generation})
	})
	return r, e
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
}

func (s *Store) CompleteRetrieval(ctx context.Context, i Identity, lease Retrieval, result RetrievalResult) error {
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		repo, e := repositoryInTx(ctx, tx, i, lease.Repository, "read")
		if e != nil {
			return e
		}
		if repo.Mode != "proxy" {
			return ErrConflict
		}
		var valid bool
		e = tx.QueryRow(ctx, `SELECT generation=$1 AND lease_token=$2 AND state='fetching' AND lease_until>clock_timestamp() FROM cratectl.retrievals WHERE repository=$3 AND path=$4 FOR UPDATE`, lease.Generation, lease.Token, lease.Repository, lease.Path).Scan(&valid)
		if e != nil {
			return e
		}
		if !valid {
			return ErrLeaseLost
		}
		state := "ready"
		fresh := result.FreshSeconds
		stale := result.StaleSeconds
		if result.Status == 200 && result.Failure == "" {
			if result.Object == nil {
				return errors.New("durable object required")
			}
			if len(result.Metadata) == 0 {
				result.Metadata = []byte(`{}`)
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
					_, e = tx.Exec(ctx, `INSERT INTO cratectl.native_sources(tenant,repository,key,format,package,coordinate,version,url,integrity,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`, i.Tenant, repo.Name, source.Key, source.Format, source.Name, source.Coordinate, source.Version, source.URL, source.Integrity, source.Metadata)
					if e != nil {
						return e
					}
				}
			}
			media := result.MediaType
			if media == "" {
				media = "application/octet-stream"
			}
			_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant,repository,path) DO UPDATE SET digest=excluded.digest,size=excluded.size,media_type=excluded.media_type,metadata=excluded.metadata,decision=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.decision ELSE 'unassessed' END,created_at=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.created_at ELSE now() END`, i.Tenant, lease.Repository, lease.Path, result.Object.Digest, result.Object.Size, media, result.Metadata)
			if e != nil {
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
		} else {
			state = "failed"
			fresh = 2
			stale = -1
			if result.Failure == "" {
				return errors.New("failure classification required")
			}
		}
		_, e = tx.Exec(ctx, `UPDATE cratectl.retrievals SET state=$1,lease_until='epoch',fresh_until=now()+make_interval(secs=>$2),stale_until=CASE WHEN $3::int<0 THEN stale_until ELSE now()+make_interval(secs=>($2+$3)) END,etag=CASE WHEN $1='negative' THEN '' WHEN $1='ready' AND $6=200 THEN $4 WHEN $1='ready' AND $4<>'' THEN $4 ELSE etag END,modified=CASE WHEN $1='negative' THEN '' WHEN $1='ready' AND $6=200 THEN $5 WHEN $1='ready' AND $5<>'' THEN $5 ELSE modified END,last_status=$6,last_error=$7,source_fresh_seconds=CASE WHEN $1='ready' THEN $2 ELSE source_fresh_seconds END,source_stale_seconds=CASE WHEN $1='ready' THEN $3 ELSE source_stale_seconds END WHERE repository=$8 AND path=$9`, state, fresh, stale, result.ETag, result.Modified, result.Status, result.Failure, lease.Repository, lease.Path)
		if e != nil {
			return e
		}
		data := map[string]any{"repository": lease.Repository, "path": lease.Path, "generation": lease.Generation, "state": state, "upstream_status": result.Status, "failure": result.Failure}
		if result.Object != nil {
			data["digest"] = result.Object.Digest
			data["size"] = result.Object.Size
		}
		return appendEvent(ctx, tx, i, "proxy.retrieval."+state, data)
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
	tag, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET generation=generation+1,lease_token='',lease_until='epoch',fresh_until='epoch',state=CASE WHEN state='fetching' THEN 'failed' ELSE state END,last_error='operator_revalidate' WHERE repository=$1 AND path=$2`, repo, path)
	if e != nil {
		return nil, e
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return map[string]string{"repository": repo, "path": path, "state": "expired", "next_action": "Next authorized request retrieves or revalidates the configured upstream."}, nil
}
