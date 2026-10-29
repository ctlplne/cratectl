// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

const schemaGateID int64 = 731445922

// Effective ownership includes privileges inherited from another owning role.
const unsafeRuntimeSQL = `SELECT r.rolsuper OR r.rolbypassrls OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl' AND pg_has_role(r.oid,c.relowner,'USAGE')) OR has_schema_privilege(r.oid,'cratectl_private','USAGE') OR COALESCE((SELECT has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl_private' AND c.relname='schema_migrations'),false) FROM pg_roles r WHERE r.rolname=current_user`

var ErrSchemaMaintenance = errors.New("schema maintenance admission closed")
var ErrSchemaIncompatible = errors.New("schema version or integrity is incompatible")
var ErrLegacyAdoption = errors.New("unversioned database needs explicit maintenance adoption")

// The session lock precedes BeginTx: a repeatable-read snapshot must not be
// captured before waiting for DDL. Cleanup never returns a locked pooled socket.
func schemaSession(ctx context.Context, c *pgx.Conn) (func(), error) {
	var admitted bool
	if e := c.QueryRow(ctx, `SELECT pg_try_advisory_lock_shared($1)`, schemaGateID).Scan(&admitted); e != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.Close(cleanup)
		return nil, e
	}
	if !admitted {
		return nil, ErrSchemaMaintenance
	}
	return func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if c.IsClosed() {
			return
		}
		if c.PgConn().TxStatus() != 'I' {
			_ = c.Close(cleanup)
			return
		}
		var unlocked bool
		if e := c.QueryRow(cleanup, `SELECT pg_advisory_unlock_shared($1)`, schemaGateID).Scan(&unlocked); e != nil || !unlocked {
			_ = c.Close(cleanup)
		}
	}, nil
}
func (s *Store) schemaTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, func(), error) {
	c, e := s.Pool.Acquire(ctx)
	if e != nil {
		return nil, nil, e
	}
	unlock, e := schemaSession(ctx, c.Conn())
	if e != nil {
		c.Release()
		return nil, nil, e
	}
	release := func() { unlock(); c.Release() }
	tx, e := c.BeginTx(ctx, options)
	if e != nil {
		release()
		return nil, nil, e
	}
	if e = checkSchema(ctx, tx, true); e != nil {
		_ = tx.Rollback(ctx)
		release()
		return nil, nil, e
	}
	return tx, release, nil
}
func ownerSchemaTx(ctx context.Context, c *pgx.Conn, initialized bool) (pgx.Tx, func(), error) {
	unlock, e := schemaSession(ctx, c)
	if e != nil {
		return nil, nil, e
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		unlock()
		return nil, nil, e
	}
	if initialized {
		if e = checkSchema(ctx, tx, false); e != nil {
			_ = tx.Rollback(ctx)
			unlock()
			return nil, nil, e
		}
	}
	return tx, unlock, nil
}
func (s *Store) Ready(ctx context.Context) error {
	tx, release, e := s.schemaTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer release()
	defer tx.Rollback(ctx)
	return tx.Commit(ctx)
}
