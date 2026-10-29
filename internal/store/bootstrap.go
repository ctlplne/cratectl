// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

type BootstrapInput struct {
	InstallationID string    `json:"installation_id"`
	Tenant         string    `json:"tenant"`
	Actor          string    `json:"actor"`
	AdminToken     string    `json:"admin_token"`
	WorkerToken    string    `json:"worker_token"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// CheckBootstrapDatabase runs before migrations, so an accidental nonempty
// database selection cannot be changed by an initializer. A matching receipt
// permits recovery of this installation after its first commit.
func CheckBootstrapDatabase(ctx context.Context, dsn string, in BootstrapInput) error {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return errors.New("initialization owner connection failed")
	}
	defer c.Close(ctx)
	tx, release, e := ownerSchemaTx(ctx, c, false)
	if e != nil {
		return e
	}
	defer release()
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SET LOCAL row_security=off; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'; SELECT pg_advisory_xact_lock(731445923)`); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, `SELECT to_regclass('cratectl.bootstrap_receipts') IS NOT NULL`).Scan(&exists); e != nil {
		return e
	}
	if exists {
		var matches bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.bootstrap_receipts WHERE tenant=$1 AND installation_id=$2 AND administrator_hash=$3 AND worker_hash=$4 AND actor=$5 AND expires_at=$6)`, in.Tenant, in.InstallationID, crypt.Digest([]byte(in.AdminToken)), crypt.Digest([]byte(in.WorkerToken)), in.Actor, in.ExpiresAt).Scan(&matches); e != nil {
			return e
		}
		if matches {
			return tx.Commit(ctx)
		}
	}
	rows, e := tx.Query(ctx, `SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','m','f') LIMIT 257`)
	if e != nil {
		return e
	}
	tables := [][2]string{}
	for rows.Next() {
		var name [2]string
		if e = rows.Scan(&name[0], &name[1]); e != nil {
			rows.Close()
			return e
		}
		tables = append(tables, name)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(tables) > 256 {
		return errors.New("database catalog exceeds the initialization inspection budget; select a dedicated empty database")
	}
	for _, name := range tables {
		if name[0] == "cratectl_private" && name[1] == "schema_migrations" {
			plan, e := inspectSchema(ctx, tx, currentMigrations())
			if e != nil || len(plan.Pending) != 0 {
				if e != nil {
					return e
				}
				return ErrSchemaIncompatible
			}
			continue
		}
		if name[0] != "cratectl" && name[0] != "cratectl_private" {
			return errors.New("database contains unrelated tables; select a dedicated empty database")
		}
		var populated bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+pgx.Identifier{name[0], name[1]}.Sanitize()+`)`).Scan(&populated); e != nil {
			return e
		}
		if populated {
			return errors.New("database already contains state; use its existing installation instead of initializing")
		}
	}
	return tx.Commit(ctx)
}

// Bootstrap commits the first tenant, credentials, audit and replay receipt
// together. Owner authority must see all rows; RLS must not hide a nonempty DB.
func Bootstrap(ctx context.Context, dsn string, in BootstrapInput) error {
	if !Name.MatchString(in.Tenant) || !Name.MatchString(in.Actor) || !uploadDigest.MatchString(in.InstallationID) || len(in.AdminToken) != 43 || len(in.WorkerToken) != 43 || in.AdminToken == in.WorkerToken || !in.ExpiresAt.After(time.Now()) {
		return errors.New("invalid or expired installation preparation")
	}
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return errors.New("initialization owner connection failed")
	}
	defer c.Close(ctx)
	tx, release, e := ownerSchemaTx(ctx, c, true)
	if e != nil {
		return e
	}
	defer release()
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SET LOCAL row_security=off; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'; SELECT pg_advisory_xact_lock(731445923)`); e != nil {
		return e
	}
	var id, admin, worker, actor string
	var expires time.Time
	e = tx.QueryRow(ctx, `SELECT installation_id,administrator_hash,worker_hash,actor,expires_at FROM cratectl.bootstrap_receipts WHERE tenant=$1`, in.Tenant).Scan(&id, &admin, &worker, &actor, &expires)
	if e == nil {
		if id != in.InstallationID || admin != crypt.Digest([]byte(in.AdminToken)) || worker != crypt.Digest([]byte(in.WorkerToken)) || actor != in.Actor || !expires.Equal(in.ExpiresAt.Truncate(time.Microsecond)) {
			return ErrConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	var occupied bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.tenants) OR EXISTS(SELECT 1 FROM cratectl_private.tokens) OR EXISTS(SELECT 1 FROM cratectl.bootstrap_receipts)`).Scan(&occupied); e != nil {
		return e
	}
	if occupied {
		return errors.New("database already contains tenant state; use the existing installation and owner provisioning commands")
	}
	if _, e = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true),pg_advisory_xact_lock(hashtextextended($1,0))`, in.Tenant); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO cratectl.tenants(tenant) VALUES($1)`, in.Tenant); e != nil {
		return e
	}
	for _, credential := range []struct{ token, actor, role string }{{in.AdminToken, in.Actor, "admin"}, {in.WorkerToken, "installation-worker", "worker"}} {
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl_private.tokens(hash,tenant,actor,role,expires_at) VALUES($1,$2,$3,$4,$5)`, crypt.Digest([]byte(credential.token)), in.Tenant, credential.actor, credential.role, in.ExpiresAt); e != nil {
			return e
		}
		if e = appendEventIntent(ctx, tx, Identity{Tenant: in.Tenant, Actor: "bootstrap", Role: "admin"}, "identity.provisioned", map[string]any{"actor": credential.actor, "role": credential.role, "expires_at": in.ExpiresAt.UTC()}, false); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO cratectl.bootstrap_receipts(tenant,installation_id,administrator_hash,worker_hash,actor,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, in.Tenant, in.InstallationID, crypt.Digest([]byte(in.AdminToken)), crypt.Digest([]byte(in.WorkerToken)), in.Actor, in.ExpiresAt); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
