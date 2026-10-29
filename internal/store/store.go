// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

//go:embed jobs.sql
var jobSchema string

//go:embed sweeps.sql
var sweepSchema string

//go:embed inventory.sql
var inventorySchema string
var Name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var ErrConflict = errors.New("conflict")
var ErrDenied = errors.New("policy denied")
var ErrNotFound = errors.New("not found")
var ErrUnauthenticated = errors.New("credential expired or revoked")

type Identity struct {
	Tenant, Actor, Role string
	CredentialHash      string
}

func (i Identity) CanWrite() bool { return i.Role == "writer" || i.Role == "admin" }

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*Store, error) {
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return nil, errors.New("invalid runtime database configuration")
	}
	var unsafe bool
	e = p.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl' AND c.relowner=r.oid) FROM pg_roles r WHERE rolname=current_user`).Scan(&unsafe)
	if e != nil || unsafe {
		p.Close()
		return nil, errors.New("runtime requires nonowner role without superuser or BYPASSRLS")
	}
	return &Store{p}, nil
}
func Migrate(ctx context.Context, dsn string) error {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return errors.New("database owner connection failed; check private configuration and database health")
	}
	defer c.Close(ctx)
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(731445922)`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, schema); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, jobSchema); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, sweepSchema); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, inventorySchema); e != nil {
		return e
	}
	// Fixed role is owned by this isolated database, never a shared production role.
	if _, e = tx.Exec(ctx, `DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='cratectl_app') THEN CREATE ROLE cratectl_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT; END IF; END $$; GRANT USAGE ON SCHEMA cratectl TO cratectl_app; GRANT EXECUTE ON FUNCTION cratectl.authenticate(text),cratectl.authenticate_worker(text) TO cratectl_app;`); e != nil {
		return e
	}
	for _, table := range []string{"tenants", "repositories", "artifacts", "events", "mutations", "jobs", "uploads", "tags", "repository_grants", "retrievals", "content_decisions", "npm_tags", "npm_sources", "native_sources", "python_yanks", "queue_policies", "event_projections", "integrity_observations", "upload_parts", "sweep_items", "inventory_entries", "inventory_observations"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		if _, e = tx.Exec(ctx, `ALTER TABLE `+q+` ENABLE ROW LEVEL SECURITY; ALTER TABLE `+q+` FORCE ROW LEVEL SECURITY; DROP POLICY IF EXISTS tenant_scope ON `+q+`; CREATE POLICY tenant_scope ON `+q+` USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true)); GRANT SELECT,INSERT ON `+q+` TO cratectl_app`); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `GRANT UPDATE ON cratectl.artifacts,cratectl.repositories,cratectl.jobs,cratectl.uploads,cratectl.tags,cratectl.repository_grants,cratectl.retrievals,cratectl.content_decisions,cratectl.npm_tags,cratectl.python_yanks,cratectl.queue_policies TO cratectl_app;`)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func Provision(ctx context.Context, dsn, tenant, actor, role, token string, expires time.Time) error {
	if !Name.MatchString(tenant) || !Name.MatchString(actor) || (role != "admin" && role != "writer" && role != "reader" && role != "worker") {
		return errors.New("invalid tenant, actor or credential role")
	}
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return errors.New("database owner connection failed; check private configuration and database health")
	}
	defer c.Close(ctx)
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.tenants(tenant) VALUES($1) ON CONFLICT DO NOTHING`, tenant)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl_private.tokens(hash,tenant,actor,role,expires_at) VALUES($1,$2,$3,$4,$5)`, crypt.Digest([]byte(token)), tenant, actor, role, expires)
	if e != nil {
		return e
	}
	if e = appendEventIntent(ctx, tx, Identity{Tenant: tenant, Actor: "bootstrap", Role: "admin"}, "identity.provisioned", map[string]any{"actor": actor, "role": role, "expires_at": expires.UTC()}, false); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Authenticate(ctx context.Context, token string) (Identity, error) {
	var i Identity
	if len(token) < 32 || len(token) > 256 {
		return i, ErrNotFound
	}
	i.CredentialHash = crypt.Digest([]byte(token))
	e := s.Pool.QueryRow(ctx, `SELECT tenant,actor,role FROM cratectl.authenticate($1)`, i.CredentialHash).Scan(&i.Tenant, &i.Actor, &i.Role)
	return i, e
}
func (s *Store) Tx(ctx context.Context, i Identity, write bool, fn func(pgx.Tx) error) error {
	options := pgx.TxOptions{}
	if !write {
		options = pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	}
	tx, e := s.Pool.BeginTx(ctx, options)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true),set_config('lock_timeout','5s',true),set_config('statement_timeout','30s',true)`, i.Tenant); e != nil {
		return e
	}
	if write {
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, i.Tenant); e != nil {
			return e
		}
	}
	if e = checkIdentity(ctx, tx, i); e != nil {
		return e
	}

	if e = fn(tx); e != nil {
		return e
	}
	if write {
		if e = checkIdentity(ctx, tx, i); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

// Recheck after bulk metadata work as well as after waiting for the tenant lock.
func checkIdentity(ctx context.Context, tx pgx.Tx, i Identity) error {
	if i.CredentialHash != "" {
		var tenant, actor, role string
		e := tx.QueryRow(ctx, `SELECT tenant,actor,role FROM cratectl.authenticate($1)`, i.CredentialHash).Scan(&tenant, &actor, &role)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if e != nil {
			return e
		}
		if tenant != i.Tenant || actor != i.Actor || role != i.Role {
			return ErrUnauthenticated
		}
	}
	return nil
}

// nextEventSequence is a mutation fence under Tx's tenant write lock. The
// enclosing mutation must append its event in this same transaction.
func nextEventSequence(ctx context.Context, tx pgx.Tx, i Identity) (int64, error) {
	var sequence int64
	e := tx.QueryRow(ctx, `SELECT COALESCE(max(sequence),0)+1 FROM cratectl.events WHERE tenant=$1`, i.Tenant).Scan(&sequence)
	return sequence, e
}

func appendEvent(ctx context.Context, tx pgx.Tx, i Identity, kind string, data any) error {
	return appendEventIntent(ctx, tx, i, kind, data, true)
}
func appendEventIntent(ctx context.Context, tx pgx.Tx, i Identity, kind string, data any, enqueue bool) error {
	var seq int64
	var prev string
	e := tx.QueryRow(ctx, `SELECT sequence,hash FROM cratectl.events WHERE tenant=$1 ORDER BY sequence DESC LIMIT 1`, i.Tenant).Scan(&seq, &prev)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	payload, e := json.Marshal(map[string]any{"tenant": i.Tenant, "actor": i.Actor, "kind": kind, "data": data, "time": time.Now().UTC().Format(time.RFC3339Nano), "sequence": seq + 1})
	if e != nil {
		return e
	}
	hash := crypt.Digest(append([]byte(prev+"\n"), payload...))
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.events(tenant,sequence,payload,previous_hash,hash) VALUES($1,$2,$3,$4,$5)`, i.Tenant, seq+1, string(payload), prev, hash)
	if e != nil {
		return e
	}
	if !enqueue {
		return nil
	}
	return enqueueEvent(ctx, tx, i, seq+1, kind)
}

type Result struct {
	Body   []byte
	Status int
	Replay bool
}

// ReplayMutation permits a recorded response to survive storage/configuration
// changes without re-running admission I/O. Authorization and fingerprint still
// apply; concurrent first admissions remain serialized by mutateIntent.
func (s *Store) ReplayMutation(ctx context.Context, i Identity, key, fingerprint string) (Result, bool, error) {
	var result Result
	found := false
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var expected string
		e := tx.QueryRow(ctx, `SELECT fingerprint,response,status FROM cratectl.mutations WHERE actor=$1 AND key=$2`, i.Actor, key).Scan(&expected, &result.Body, &result.Status)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if expected != fingerprint {
			return ErrConflict
		}
		found = true
		result.Replay = true
		return nil
	})
	return result, found, e
}

// Mutate commits the effect, response, event and outbox together.
func (s *Store) Mutate(ctx context.Context, i Identity, key, fingerprint, kind string, fn func(pgx.Tx) (any, int, error)) (Result, error) {
	return s.mutateIntent(ctx, i, key, fingerprint, kind, true, fn)
}
func (s *Store) mutateIntent(ctx context.Context, i Identity, key, fingerprint, kind string, enqueue bool, fn func(pgx.Tx) (any, int, error)) (Result, error) {
	var res Result
	e := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		if key != "" {
			var fp string
			e := tx.QueryRow(ctx, `SELECT fingerprint,response,status FROM cratectl.mutations WHERE actor=$1 AND key=$2`, i.Actor, key).Scan(&fp, &res.Body, &res.Status)
			if e == nil {
				if fp != fingerprint {
					return ErrConflict
				}
				res.Replay = true
				return nil
			}
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		}
		data, status, e := fn(tx)
		if e != nil {
			return e
		}
		res.Status = status
		res.Body, e = json.Marshal(data)
		if e != nil {
			return e
		}
		if e = appendEventIntent(ctx, tx, i, kind, data, enqueue); e != nil {
			return e
		}
		if key != "" {
			_, e = tx.Exec(ctx, `INSERT INTO cratectl.mutations(tenant,actor,key,fingerprint,response,status) VALUES($1,$2,$3,$4,$5,$6)`, i.Tenant, i.Actor, key, fingerprint, res.Body, status)
		}
		return e
	})
	return res, e
}

type Artifact struct {
	Repository string          `json:"repository"`
	Path       string          `json:"path"`
	Digest     string          `json:"digest"`
	Size       int64           `json:"size"`
	MediaType  string          `json:"media_type"`
	Metadata   json.RawMessage `json:"metadata"`
	Decision   string          `json:"decision"`
	Created    time.Time       `json:"created_at"`
}

func scanArtifact(row pgx.Row, a *Artifact) error {
	return row.Scan(&a.Repository, &a.Path, &a.Digest, &a.Size, &a.MediaType, &a.Metadata, &a.Decision, &a.Created)
}

// Artifacts returns metadata only for currently servable objects unless an admin
// explicitly requests an inventory. This is shared by protocol metadata paths.
func (s *Store) Artifacts(ctx context.Context, i Identity, repo, prefix string, inventory bool) ([]Artifact, error) {
	out := []Artifact{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := repositoryInTx(ctx, tx, i, repo, "read"); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository) `+decisionJoin+` WHERE a.repository=$1 AND starts_with(a.path,$2) AND ($3 OR (COALESCE(d.decision,a.decision)<>'denied' AND (NOT r.require_review OR COALESCE(d.decision,a.decision)='allowed'))) ORDER BY a.path LIMIT 1000`, repo, prefix, inventory && i.Role == "admin")
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a Artifact
			if e = scanArtifact(rows, &a); e != nil {
				return e
			}
			out = append(out, a)
		}
		err := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !inventory || i.Role != "admin" {
			var review bool
			if err = tx.QueryRow(ctx, `SELECT require_review FROM cratectl.repositories WHERE name=$1`, repo).Scan(&review); err != nil {
				return err
			}
			filtered := out[:0]
			for _, artifact := range out {
				if isManifest(artifact.MediaType) {
					_, err = readArtifact(ctx, tx, repo, artifact.Path, review, newGraphBudget())
					if errors.Is(err, ErrDenied) || errors.Is(err, ErrNotFound) {
						continue
					}
					if err != nil {
						return err
					}
				}
				filtered = append(filtered, artifact)
			}
			out = filtered
		}

		return rows.Err()
	})
	return out, e
}
func InsertArtifacts(ctx context.Context, tx pgx.Tx, i Identity, repo string, as []Artifact) error {
	r, e := repositoryInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return e
	}
	if r.Mode != "hosted" {
		return ErrDenied
	}
	for _, a := range as {
		if a.Metadata == nil {
			a.Metadata = json.RawMessage(`{}`)
		}
		tag, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, i.Tenant, repo, a.Path, a.Digest, a.Size, a.MediaType, a.Metadata)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			var digest string
			if e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, a.Path).Scan(&digest); e != nil {
				return e
			}
			if digest != a.Digest {
				return fmt.Errorf("%w: coordinate already contains different bytes", ErrConflict)
			}
		}
	}
	return enqueueIntegrity(ctx, tx, i, repo, as)
}
func (s *Store) Publish(ctx context.Context, i Identity, repo string, as []Artifact) error {
	if !i.CanWrite() {
		return ErrDenied
	}
	_, e := s.Mutate(ctx, i, "", "", "artifact.published", func(tx pgx.Tx) (any, int, error) {
		if e := InsertArtifacts(ctx, tx, i, repo, as); e != nil {
			return nil, 0, e
		}
		return as, 201, nil
	})
	return e
}

type Event struct {
	Sequence     int64  `json:"sequence"`
	Payload      string `json:"payload"`
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
}

func (s *Store) Events(ctx context.Context, i Identity, after int64) ([]Event, error) {
	if i.Role != "admin" {
		return nil, ErrDenied
	}
	out := []Event{}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT sequence,payload,previous_hash,hash FROM cratectl.events WHERE sequence>$1 ORDER BY sequence LIMIT 1000`, after)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v Event
			if e = rows.Scan(&v.Sequence, &v.Payload, &v.PreviousHash, &v.Hash); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, e
}

// ReplaceMetadata changes a native mutable metadata reference. The old and new
// immutable object identities remain in the journal, and any manual decision
// on the old bytes is deliberately reset for the replacement bytes.
func (s *Store) ReplaceMetadata(ctx context.Context, i Identity, repo string, a Artifact) error {
	if !i.CanWrite() {
		return ErrDenied
	}
	_, e := s.Mutate(ctx, i, "", "", "metadata.replaced", func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Mode != "hosted" {
			return nil, 0, ErrDenied
		}
		var old string
		e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, a.Path).Scan(&old)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, 0, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant,repository,path) DO UPDATE SET digest=excluded.digest,size=excluded.size,media_type=excluded.media_type,decision=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.decision ELSE 'unassessed' END,created_at=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.created_at ELSE now() END`, i.Tenant, repo, a.Path, a.Digest, a.Size, a.MediaType)
		if e == nil {
			e = enqueueIntegrity(ctx, tx, i, repo, []Artifact{a})
		}
		return map[string]any{"repository": repo, "path": a.Path, "previous_digest": old, "digest": a.Digest, "size": a.Size}, 201, e
	})
	return e
}

// Revoke is an explicit emergency owner operation; it never returns credential
// material or grants the provider an artifact-serving identity.
func Revoke(ctx context.Context, dsn, token string) error {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return errors.New("database owner connection failed")
	}
	defer c.Close(ctx)
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var tenant, actor string
	e = tx.QueryRow(ctx, `SELECT tenant,actor FROM cratectl_private.tokens WHERE hash=$1`, crypt.Digest([]byte(token))).Scan(&tenant, &actor)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, crypt.Digest([]byte(token))); e != nil {
		return e
	}
	if e = appendEventIntent(ctx, tx, Identity{Tenant: tenant, Actor: "bootstrap", Role: "admin"}, "identity.revoked", map[string]string{"actor": actor}, false); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
