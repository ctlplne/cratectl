//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/testdb"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/url"
	"testing"
	"time"
)

func TestSchemaFreshCurrentAndPrivateReceipts(t *testing.T) {
	d := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || plan.DatabaseState != "empty" || len(plan.Pending) != len(currentMigrations()) {
		t.Fatal("empty plan", plan, e)
	}
	if e = Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal("fresh migration", e)
	}
	plan, e = MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || plan.DatabaseState != "current" || len(plan.Applied) != len(currentMigrations()) || !plan.SafetyValid {
		t.Fatal("current plan", plan, e)
	}
	db, e := Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal("runtime open", e)
	}
	defer db.Pool.Close()
	token, _ := crypt.Token()
	if e = Provision(ctx, d.OwnerDSN, "schema-team", "operator", "admin", token, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, i, Repository{Name: "first-repo", Format: "generic"})
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Pool.Exec(ctx, `SELECT * FROM cratectl_private.schema_migrations`); e == nil {
		t.Fatal("runtime read private migration receipts")
	}
	// Hold a real runtime transaction over authentication and repository tables.
	// A repeated migration must stay read-only and must not wait for this lease.
	tx, release, e := db.schemaTx(ctx, pgx.TxOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT tenant FROM cratectl.authenticate($1);`, i.CredentialHash); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `SELECT name FROM cratectl.repositories LIMIT 1`); e != nil {
		t.Fatal(e)
	}
	noop, cancelNoop := context.WithTimeout(ctx, 2*time.Second)
	defer cancelNoop()
	if e = Migrate(noop, d.OwnerDSN); e != nil {
		t.Fatal("current migration blocked live transaction", e)
	}
}

func schemaFixture(t *testing.T) (testdb.Database, *Store, *pgx.Conn, string, string) {
	t.Helper()
	d := testdb.New(t)
	ctx := context.Background()
	if e := Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	db, e := Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Pool.Close)
	c, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	token, _ := crypt.Token()
	worker, _ := crypt.Token()
	for _, credential := range []struct{ role, token string }{{"admin", token}, {"worker", worker}} {
		if e = Provision(ctx, d.OwnerDSN, "schema-team", credential.role, credential.role, credential.token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	return d, db, c, token, worker
}

func namedSchemaDSN(t *testing.T, dsn, name string) string {
	t.Helper()
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal("parse fixture DSN")
	}
	q := u.Query()
	q.Set("application_name", name)
	u.RawQuery = q.Encode()
	return u.String()
}

func waitSchemaBackend(t *testing.T, c *pgx.Conn, name string, waiting bool) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var pid uint32
		var e error
		if waiting {
			e = c.QueryRow(ctx, `SELECT a.pid FROM pg_stat_activity a JOIN pg_locks l ON a.pid=l.pid WHERE a.datname=current_database() AND a.application_name=$1 AND l.locktype='advisory' AND NOT l.granted AND l.objid=$2`, name, schemaGateID).Scan(&pid)
		} else {
			e = c.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='active' AND wait_event='PgSleep'`, name).Scan(&pid)
		}
		if e == nil {
			return pid
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			t.Fatal(e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("migration did not reach expected database barrier", name, waiting)
	return 0
}

func futureSchemaStep(sql string) []migrationStep {
	return append(currentMigrations(), migrationStep{len(currentMigrations()) + 1, "owned future-version fixture", sql})
}

func TestSchemaDrainQueueAndFutureVersion(t *testing.T) {
	d, db, owner, token, worker := schemaFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, release, e := db.schemaTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	held := true
	defer func() {
		if held {
			_ = tx.Rollback(context.Background())
			release()
		}
	}()
	if _, e = tx.Exec(ctx, `SELECT tenant FROM cratectl.authenticate($1)`, crypt.Digest([]byte(token))); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	steps := futureSchemaStep(`CREATE TABLE cratectl_private.gate_probe(id integer PRIMARY KEY); INSERT INTO cratectl_private.gate_probe VALUES(1)`)
	go func() {
		done <- migrateSteps(ctx, namedSchemaDSN(t, d.OwnerDSN, "cratectl-schema-drain"), MigrationOptions{}, steps)
	}()
	waitSchemaBackend(t, owner, "cratectl-schema-drain", true)
	if _, e = db.Authenticate(ctx, token); !errors.Is(e, ErrSchemaMaintenance) {
		t.Fatal("authentication during queued DDL", e)
	}
	if _, e = db.AuthenticateWorker(ctx, worker); !errors.Is(e, ErrSchemaMaintenance) {
		t.Fatal("worker during queued DDL", e)
	}
	if e = db.Ready(ctx); !errors.Is(e, ErrSchemaMaintenance) {
		t.Fatal("readiness during queued DDL", e)
	}
	if _, e = MigrationPlan(ctx, d.OwnerDSN); !errors.Is(e, ErrSchemaMaintenance) {
		t.Fatal("plan during queued DDL", e)
	}
	if e = Revoke(ctx, d.OwnerDSN, token); !errors.Is(e, ErrSchemaMaintenance) {
		t.Fatal("revocation during queued DDL", e)
	}
	if e = db.Tx(ctx, Identity{Tenant: "schema-team", Actor: "admin", Role: "admin"}, true, func(pgx.Tx) error { t.Error("new mutation admitted"); return nil }); !errors.Is(e, ErrSchemaMaintenance) {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		t.Fatal("migration passed admitted transaction", e)
	default:
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal("admitted transaction did not drain", e)
	}
	release()
	held = false
	if e = <-done; e != nil {
		t.Fatal("migration after drain", e)
	}
	var n int
	if e = owner.QueryRow(ctx, `SELECT count(*) FROM cratectl_private.gate_probe`).Scan(&n); e != nil || n != 1 {
		t.Fatal("future effect", n, e)
	}
	for label, operation := range map[string]func() error{
		"readiness":           func() error { return db.Ready(ctx) },
		"authentication":      func() error { _, e := db.Authenticate(ctx, token); return e },
		"worker":              func() error { _, e := db.AuthenticateWorker(ctx, worker); return e },
		"migration downgrade": func() error { return Migrate(ctx, d.OwnerDSN) },
	} {
		if e = operation(); !errors.Is(e, ErrSchemaIncompatible) {
			t.Fatal(label, e)
		}
	}
	plan, e := inspectSchema(ctx, owner, steps)
	if e != nil || plan.BinaryVersion != len(steps) || len(plan.Applied) != len(steps) || len(plan.Pending) != 0 {
		t.Fatal("future fixture plan", plan, e)
	}
}

func TestSchemaDriftFailsClosed(t *testing.T) {
	cases := map[string]string{
		"checksum":              `UPDATE cratectl_private.schema_migrations SET checksum=repeat('a',64) WHERE version=1`,
		"gap":                   `DELETE FROM cratectl_private.schema_migrations WHERE version=1`,
		"unknown version":       `INSERT INTO cratectl_private.schema_migrations(version,checksum)VALUES(4,repeat('a',64))`,
		"RLS disabled":          `ALTER TABLE cratectl.artifacts DISABLE ROW LEVEL SECURITY`,
		"RLS not forced":        `ALTER TABLE cratectl.repositories NO FORCE ROW LEVEL SECURITY`,
		"extra policy":          `CREATE POLICY bypass ON cratectl.artifacts USING(true)`,
		"weakened read policy":  `ALTER POLICY tenant_scope ON cratectl.artifacts USING(true)`,
		"weakened write policy": `ALTER POLICY tenant_scope ON cratectl.artifacts WITH CHECK(true)`,
		"function body":         `CREATE OR REPLACE FUNCTION cratectl.schema_state() RETURNS TABLE(version integer,history jsonb,safety_valid boolean) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$SELECT 2,'[]'::jsonb,true$$`,
		"public function":       `GRANT EXECUTE ON FUNCTION cratectl.schema_state() TO PUBLIC`,
		"missing function":      `DROP FUNCTION cratectl.schema_state()`,
		"missing ledger":        `DROP TABLE cratectl_private.schema_migrations`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			d, db, owner, token, worker := schemaFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, e := owner.Exec(ctx, sql); e != nil {
				t.Fatal(e)
			}
			for label, operation := range map[string]func() error{
				"authentication": func() error { _, e := db.Authenticate(ctx, token); return e },
				"worker":         func() error { _, e := db.AuthenticateWorker(ctx, worker); return e },
				"readiness":      func() error { return db.Ready(ctx) },
				"mutation": func() error {
					return db.Tx(ctx, Identity{Tenant: "schema-team", Actor: "admin", Role: "admin"}, true, func(pgx.Tx) error { t.Error("unsafe mutation admitted"); return nil })
				},
				"migration": func() error { return Migrate(ctx, d.OwnerDSN) },
			} {
				if e := operation(); !errors.Is(e, ErrSchemaIncompatible) {
					t.Fatal(label, e)
				}
			}
		})
	}
}

func TestSchemaInterruptedAndFailedDDLIsAtomic(t *testing.T) {
	for _, mode := range []string{"failure", "cancel", "terminate"} {
		t.Run(mode, func(t *testing.T) {
			d, db, owner, token, _ := schemaFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			sql := `CREATE TABLE cratectl_private.rollback_probe(id integer)`
			if mode == "failure" {
				sql += `;SELECT 1/0`
			} else {
				sql += `;SELECT pg_sleep(30)`
			}
			done := make(chan error, 1)
			dsn := namedSchemaDSN(t, d.OwnerDSN, "cratectl-schema-interrupt")
			go func() { done <- migrateSteps(ctx, dsn, MigrationOptions{}, futureSchemaStep(sql)) }()
			if mode != "failure" {
				pid := waitSchemaBackend(t, owner, "cratectl-schema-interrupt", false)
				if _, e := db.Authenticate(context.Background(), token); !errors.Is(e, ErrSchemaMaintenance) {
					t.Fatal("active migration admitted request", e)
				}
				if mode == "cancel" {
					cancel()
				} else {
					if _, e := owner.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, pid); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e := <-done; e == nil {
				t.Fatal("interrupted migration succeeded")
			}
			verify, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			var absent bool
			var receipts int
			if e := owner.QueryRow(verify, `SELECT to_regclass('cratectl_private.rollback_probe') IS NULL,(SELECT count(*) FROM cratectl_private.schema_migrations)`).Scan(&absent, &receipts); e != nil || !absent || receipts != len(currentMigrations()) {
				t.Fatal("partial DDL or receipt survived", absent, receipts, e)
			}
			for {
				_, e := db.Authenticate(verify, token)
				if e == nil {
					break
				}
				if !errors.Is(e, ErrSchemaMaintenance) || verify.Err() != nil {
					t.Fatal("credential or gate not recovered", e)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if e := Migrate(verify, d.OwnerDSN); e != nil {
				t.Fatal("migration retry", e)
			}
		})
	}
}

func TestSchemaConcurrentMigratorsAndCanceledSession(t *testing.T) {
	d := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 2)
	for n := 0; n < 2; n++ {
		go func() { done <- Migrate(ctx, d.OwnerDSN) }()
	}
	for n := 0; n < 2; n++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	db, e := Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	lease, cancelLease := context.WithCancel(ctx)
	tx, release, e := db.schemaTx(lease, pgx.TxOptions{})
	if e != nil {
		t.Fatal(e)
	}
	cancelLease()
	_ = tx.Rollback(lease)
	release()
	if e = db.Ready(ctx); e != nil {
		t.Fatal("pooled canceled session retained gate", e)
	}
	steps := currentMigrations()
	steps[0].SQL += "\nSELECT 1;"
	if e = migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("modified applied migration accepted", e)
	}
	if e = db.Ready(ctx); e != nil {
		t.Fatal(e)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	probe, e := owner.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer probe.Rollback(ctx)
	var exclusive bool
	if e = probe.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, schemaGateID).Scan(&exclusive); e != nil || !exclusive {
		t.Fatal("canceled runtime session leaked its shared gate", e)
	}
}

func TestSchemaRuntimeRoleDrift(t *testing.T) {
	for _, mode := range []string{"bypass", "superuser", "owner", "inherited-owner", "private-usage", "private-table"} {
		t.Run(mode, func(t *testing.T) {
			d, _, owner, token, _ := schemaFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			secret, _ := crypt.Token()
			role := "cratectl_schema_" + crypt.Digest([]byte(secret))[:16]
			// Owned unique roles avoid changing the shared test login in other suites.
			if _, e := owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOBYPASSRLS PASSWORD '`+secret+`';GRANT cratectl_app TO `+pgx.Identifier{role}.Sanitize()); e != nil {
				t.Fatal("create owned runtime role")
			}
			t.Cleanup(func() {
				c, e := pgx.Connect(context.Background(), d.OwnerDSN)
				if e != nil {
					t.Error("role cleanup connection")
					return
				}
				defer c.Close(context.Background())
				if _, e = c.Exec(context.Background(), `REASSIGN OWNED BY `+pgx.Identifier{role}.Sanitize()+` TO CURRENT_USER;DROP OWNED BY `+pgx.Identifier{role}.Sanitize()+`;DROP ROLE `+pgx.Identifier{role}.Sanitize()); e != nil {
					t.Error("owned runtime role cleanup")
				}
			})
			u, e := url.Parse(d.RuntimeDSN)
			if e != nil {
				t.Fatal("fixture URL")
			}
			u.User = url.UserPassword(role, secret)
			db, e := Open(ctx, u.String())
			if e != nil {
				t.Fatal("safe isolated runtime", e)
			}
			defer db.Pool.Close()
			if _, e = db.Authenticate(ctx, token); e != nil {
				t.Fatal(e)
			}
			q := pgx.Identifier{role}.Sanitize()
			sql := ""
			switch mode {
			case "bypass":
				sql = `ALTER ROLE ` + q + ` BYPASSRLS`
			case "superuser":
				sql = `ALTER ROLE ` + q + ` SUPERUSER`
			case "owner":
				sql = `ALTER TABLE cratectl.artifacts OWNER TO ` + q
			case "inherited-owner":
				sql = `GRANT ` + pgx.Identifier{owner.Config().User}.Sanitize() + ` TO ` + q
			case "private-usage":
				sql = `GRANT USAGE ON SCHEMA cratectl_private TO ` + q
			case "private-table":
				sql = `GRANT SELECT ON TABLE cratectl_private.schema_migrations TO ` + q
			}
			if _, e = owner.Exec(ctx, sql); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Authenticate(ctx, token); !errors.Is(e, ErrSchemaIncompatible) {
				t.Fatal("unsafe role authenticated", mode, e)
			}
			if e = db.Ready(ctx); !errors.Is(e, ErrSchemaIncompatible) {
				t.Fatal("unsafe role ready", mode, e)
			}
		})
	}
}
func TestSchemaLegacyRequiresAcknowledgement(t *testing.T) {
	d := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	if _, e = c.Exec(ctx, legacySchemaSQL()); e != nil {
		t.Fatal(e)
	}
	if e = Migrate(ctx, d.OwnerDSN); !errors.Is(e, ErrLegacyAdoption) {
		t.Fatal("legacy adopted without maintenance acknowledgement", e)
	}
	if e = MigrateWithOptions(ctx, d.OwnerDSN, MigrationOptions{AdoptLegacy: true}); e != nil {
		t.Fatal("explicit legacy adoption", e)
	}
	db, e := Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	db.Pool.Close()
}
