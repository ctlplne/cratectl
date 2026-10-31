// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"time"
)

const migrationLedgerSQL = `CREATE SCHEMA IF NOT EXISTS cratectl_private;
REVOKE ALL ON SCHEMA cratectl_private FROM PUBLIC;
CREATE TABLE IF NOT EXISTS cratectl_private.schema_migrations(version integer PRIMARY KEY CHECK(version>0),checksum text NOT NULL CHECK(checksum ~ '^[a-f0-9]{64}$'),applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON TABLE cratectl_private.schema_migrations FROM PUBLIC,cratectl_app;`

type migrationStep struct {
	Version   int
	Name, SQL string
}
type SchemaReceipt struct {
	Version  int    `json:"version"`
	Checksum string `json:"checksum"`
}
type SchemaPlan struct {
	BinaryVersion          int             `json:"binary_version"`
	DatabaseState          string          `json:"database_state"`
	Applied                []SchemaReceipt `json:"applied"`
	Pending                []int           `json:"pending"`
	RequiresLegacyAdoption bool            `json:"requires_legacy_adoption"`
	SafetyValid            bool            `json:"safety_valid"`
}
type MigrationOptions struct{ AdoptLegacy bool }

func migrationSafetySQL() string {
	return migrationSafetySQLFor(schemaTablesV1)
}

func migrationSafetySQLFor(tables []string) string {
	names := []string{}
	for _, name := range tables {
		names = append(names, "('"+name+"')")
	}
	return `SELECT count(*)=` + fmt.Sprint(len(tables)) + ` AND COALESCE(bool_and(c.relrowsecurity AND c.relforcerowsecurity AND (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)=1 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant_scope' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND regexp_replace(pg_get_expr(p.polqual,p.polrelid),'\s','','g')='(tenant=current_setting(''cratectl.tenant''::text,true))' AND regexp_replace(pg_get_expr(p.polwithcheck,p.polrelid),'\s','','g')='(tenant=current_setting(''cratectl.tenant''::text,true))')),false) FROM (VALUES ` + strings.Join(names, ",") + `) expected(name) LEFT JOIN pg_namespace n ON n.nspname='cratectl' LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=expected.name AND c.relkind IN ('r','p')`
}
func buildSchemaStateBody() string {
	return `SELECT (SELECT COALESCE(max(version),0) FROM cratectl_private.schema_migrations),COALESCE((SELECT jsonb_agg(to_jsonb(h) ORDER BY h.version) FROM (SELECT version,checksum FROM cratectl_private.schema_migrations ORDER BY version LIMIT 129)h),'[]'::jsonb),(` + migrationSafetySQL() + `)`
}

var frozenSchemaStateBody = buildSchemaStateBody()
var lifecycleSchemaStateBody = strings.Replace(frozenSchemaStateBody, migrationSafetySQL(), migrationSafetySQLFor(schemaTablesV3), 1)
var sourceSchemaStateBody = strings.Replace(frozenSchemaStateBody, migrationSafetySQL(), migrationSafetySQLFor(schemaTablesV4), 1)
var scheduleSchemaStateBody = strings.Replace(frozenSchemaStateBody, migrationSafetySQL(), migrationSafetySQLFor(schemaTablesV6), 1)
var retentionSchemaStateBody = strings.Replace(frozenSchemaStateBody, migrationSafetySQL(), migrationSafetySQLFor(schemaTablesV7), 1)
var retentionScheduleSchemaStateBody = strings.Replace(frozenSchemaStateBody, migrationSafetySQL(), migrationSafetySQLFor(schemaTablesV8), 1)

func schemaStateBody() string { return frozenSchemaStateBody }
func schemaStateBodyForVersion(version int) string {
	if version >= 8 {
		return retentionScheduleSchemaStateBody
	}
	if version >= 7 {
		return retentionSchemaStateBody
	}
	if version >= 6 {
		return scheduleSchemaStateBody
	}
	if version >= 4 {
		return sourceSchemaStateBody
	}
	if version >= 3 {
		return lifecycleSchemaStateBody
	}
	return frozenSchemaStateBody
}

func schemaStateSQL(body string) string {
	return `CREATE OR REPLACE FUNCTION cratectl.schema_state() RETURNS TABLE(version integer,history jsonb,safety_valid boolean) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $schema$` + body + `$schema$;REVOKE ALL ON FUNCTION cratectl.schema_state() FROM PUBLIC;GRANT EXECUTE ON FUNCTION cratectl.schema_state() TO cratectl_app;`
}

func buildMigrations() []migrationStep {
	body := schemaStateBody()
	state := schemaStateSQL(body)
	lifecycle := lifecycleSchema
	for _, table := range []string{"artifact_lifecycle", "repository_lifecycle"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		lifecycle += `ALTER TABLE ` + q + ` ENABLE ROW LEVEL SECURITY; ALTER TABLE ` + q + ` FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON ` + q + ` USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true)); GRANT SELECT,INSERT,UPDATE ON ` + q + ` TO cratectl_app;`
	}
	lifecycle += schemaStateSQL(lifecycleSchemaStateBody)
	schedules := integrityScheduleSchema
	for _, table := range []string{"integrity_schedules", "integrity_schedule_revisions", "integrity_schedule_runs"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		schedules += `ALTER TABLE ` + q + ` ENABLE ROW LEVEL SECURITY; ALTER TABLE ` + q + ` FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON ` + q + ` USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true)); GRANT SELECT,INSERT ON ` + q + ` TO cratectl_app;`
	}
	schedules += `GRANT UPDATE ON cratectl.integrity_schedules TO cratectl_app;` + schemaStateSQL(scheduleSchemaStateBody)
	retention := retentionSchema
	for _, table := range []string{"retention_policies", "retention_revisions", "retention_runs", "retention_items", "retention_observations"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		retention += `ALTER TABLE ` + q + ` ENABLE ROW LEVEL SECURITY; ALTER TABLE ` + q + ` FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON ` + q + ` USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true)); GRANT SELECT,INSERT ON ` + q + ` TO cratectl_app;`
	}
	retention += `GRANT UPDATE ON cratectl.retention_policies TO cratectl_app;` + schemaStateSQL(retentionSchemaStateBody)
	retentionSchedules := retentionScheduleSchema
	for _, table := range []string{"retention_schedules", "retention_schedule_revisions", "retention_schedule_runs"} {
		q := pgx.Identifier{"cratectl", table}.Sanitize()
		retentionSchedules += `ALTER TABLE ` + q + ` ENABLE ROW LEVEL SECURITY; ALTER TABLE ` + q + ` FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON ` + q + ` USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true)); GRANT SELECT,INSERT ON ` + q + ` TO cratectl_app;`
	}
	retentionSchedules += `GRANT UPDATE ON cratectl.retention_schedules TO cratectl_app;` + schemaStateSQL(retentionScheduleSchemaStateBody)
	return []migrationStep{{1, "legacy baseline", legacySchemaSQL()}, {2, "schema state and runtime coordination", migrationLedgerSQL + "\n" + state}, {3, "retained artifact and repository lifecycle", lifecycle}, {4, "versioned repository source configuration", sourceConfigurationSchema + schemaStateSQL(sourceSchemaStateBody)}, {5, "fenced exact-byte repair jobs", schemaStateSQL(sourceSchemaStateBody)}, {6, "recurring bounded integrity sampling", schedules}, {7, "policy-driven retained retirement", retention}, {8, "explicitly authorized scheduled retirement", retentionSchedules}, {9, "bounded hold inventory and immutable lifecycle history", holdManagementSchema + schemaStateSQL(retentionScheduleSchemaStateBody)}}
}

var frozenMigrations = buildMigrations()
var frozenChecksums = func() []string {
	checksums := make([]string, len(frozenMigrations))
	for n, step := range frozenMigrations {
		checksums[n] = hashMigration(step)
	}
	return checksums
}()

func currentMigrations() []migrationStep { return append([]migrationStep(nil), frozenMigrations...) }
func migrationChecksum(s migrationStep) string {
	for n, step := range frozenMigrations {
		if step == s {
			return frozenChecksums[n]
		}
	}
	return hashMigration(s)
}
func hashMigration(s migrationStep) string {
	return crypt.Digest([]byte(fmt.Sprint(s.Version) + "\n" + s.Name + "\n" + s.SQL))
}
func validateReceipts(receipts []SchemaReceipt, steps []migrationStep) error {
	if len(receipts) > len(steps) {
		return ErrSchemaIncompatible
	}
	for n, r := range receipts {
		if r.Version != steps[n].Version || r.Checksum != migrationChecksum(steps[n]) {
			return ErrSchemaIncompatible
		}
	}
	return nil
}
func checkSchema(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, runtime bool) error {
	return checkSchemaPlan(ctx, q, currentMigrations(), runtime)
}
func checkSchemaPlan(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, steps []migrationStep, runtime bool) (result error) {
	defer func() {
		var databaseError *pgconn.PgError
		if errors.As(result, &databaseError) {
			switch databaseError.Code {
			case "42P01", "42883", "42501", "42703", "3F000":
				result = ErrSchemaIncompatible
			}
		}
	}()
	var correct bool
	e := q.QueryRow(ctx, `SELECT COALESCE((SELECT p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog']::text[] AND p.prosrc=$1 AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='sql') AND (NOT $2::boolean OR p.proowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)) AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='cratectl' AND p.proname='schema_state' AND p.pronargs=0),false)`, schemaStateBodyForVersion(steps[len(steps)-1].Version), runtime).Scan(&correct)
	if e != nil {
		return e
	}
	if !correct {
		return ErrSchemaIncompatible
	}
	var version int
	var data []byte
	var safe bool
	if e = q.QueryRow(ctx, `SELECT version,history,safety_valid FROM cratectl.schema_state()`).Scan(&version, &data, &safe); e != nil {
		return e
	}
	var receipts []SchemaReceipt
	if len(data) > 32<<10 || json.Unmarshal(data, &receipts) != nil || !safe || version != steps[len(steps)-1].Version || len(receipts) != len(steps) || validateReceipts(receipts, steps) != nil {
		return ErrSchemaIncompatible
	}
	if runtime {
		var unsafe bool
		if e = q.QueryRow(ctx, unsafeRuntimeSQL).Scan(&unsafe); e != nil {
			return e
		}
		if unsafe {
			return ErrSchemaIncompatible
		}
	}
	return nil
}
func inspectSchema(ctx context.Context, c interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, steps []migrationStep) (SchemaPlan, error) {
	plan := SchemaPlan{BinaryVersion: steps[len(steps)-1].Version, Applied: []SchemaReceipt{}, Pending: []int{}}
	var ledger, legacy, stateFunction bool
	if e := c.QueryRow(ctx, `SELECT to_regclass('cratectl_private.schema_migrations') IS NOT NULL,to_regnamespace('cratectl') IS NOT NULL OR to_regclass('cratectl_private.tokens') IS NOT NULL,EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='cratectl' AND p.proname='schema_state')`).Scan(&ledger, &legacy, &stateFunction); e != nil {
		return plan, e
	}
	if !ledger && stateFunction {
		return plan, ErrSchemaIncompatible
	}
	if ledger {
		rows, e := c.Query(ctx, `SELECT version,checksum FROM cratectl_private.schema_migrations ORDER BY version LIMIT $1`, len(steps)+1)
		if e != nil {
			return plan, e
		}
		for rows.Next() {
			var r SchemaReceipt
			if e = rows.Scan(&r.Version, &r.Checksum); e != nil {
				rows.Close()
				return plan, e
			}
			plan.Applied = append(plan.Applied, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return plan, e
		}
		if e = validateReceipts(plan.Applied, steps); e != nil {
			return plan, e
		}
	}
	for n := len(plan.Applied); n < len(steps); n++ {
		plan.Pending = append(plan.Pending, steps[n].Version)
	}
	if len(plan.Applied) >= 2 && len(plan.Pending) > 0 {
		if e := checkSchemaPlan(ctx, c, steps[:len(plan.Applied)], false); e != nil {
			return plan, e
		}
		plan.SafetyValid = true
	}
	if len(plan.Pending) == 0 {
		if e := checkSchemaPlan(ctx, c, steps, false); e != nil {
			return plan, e
		}
		plan.DatabaseState = "current"
		plan.SafetyValid = true
	} else if !ledger && legacy {
		plan.DatabaseState = "legacy"
		plan.RequiresLegacyAdoption = true
	} else {
		plan.DatabaseState = "empty"
		if ledger {
			plan.DatabaseState = "pending"
		}
	}
	return plan, nil
}
func MigrationPlan(ctx context.Context, dsn string) (SchemaPlan, error) {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return SchemaPlan{}, errors.New("database owner connection failed")
	}
	defer c.Close(ctx)
	unlock, e := schemaSession(ctx, c)
	if e != nil {
		return SchemaPlan{}, e
	}
	defer unlock()
	return inspectSchema(ctx, c, currentMigrations())
}
func Migrate(ctx context.Context, dsn string) error {
	return MigrateWithOptions(ctx, dsn, MigrationOptions{})
}
func MigrateWithOptions(ctx context.Context, dsn string, options MigrationOptions) error {
	return migrateSteps(ctx, dsn, options, currentMigrations())
}
func migrateSteps(ctx context.Context, dsn string, options MigrationOptions, steps []migrationStep) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return errors.New("database owner connection failed; check private configuration and database health")
	}
	defer c.Close(ctx)
	// A true no-op must not queue exclusive admission or execute any DDL.
	unlock, e := schemaSession(ctx, c)
	if e == nil {
		plan, check := inspectSchema(ctx, c, steps)
		unlock()
		if check != nil {
			return check
		}
		if len(plan.Pending) == 0 {
			return nil
		}
		if plan.RequiresLegacyAdoption && !options.AdoptLegacy {
			return ErrLegacyAdoption
		}
	} else if !errors.Is(e, ErrSchemaMaintenance) {
		return e
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, e = tx.Exec(ctx, `SET LOCAL lock_timeout='30s';SET LOCAL statement_timeout='60s'`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, schemaGateID); e != nil {
		return e
	}
	plan, e := inspectSchema(ctx, tx, steps)
	if e != nil {
		return e
	}
	if len(plan.Pending) == 0 {
		return tx.Commit(ctx)
	}
	if plan.RequiresLegacyAdoption && !options.AdoptLegacy {
		return ErrLegacyAdoption
	}
	// Bootstrap the ledger only under exclusive admission, in the same transaction.
	// The runtime role may not exist on an empty target, so revoke PUBLIC now and
	// revoke its explicit table privileges in migration 2 after the baseline.
	if _, e = tx.Exec(ctx, strings.Replace(migrationLedgerSQL, "FROM PUBLIC,cratectl_app", "FROM PUBLIC", 1)); e != nil {
		return e
	}
	for n := len(plan.Applied); n < len(steps); n++ {
		step := steps[n]
		if _, e = tx.Exec(ctx, step.SQL); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl_private.schema_migrations(version,checksum)VALUES($1,$2)`, step.Version, migrationChecksum(step)); e != nil {
			return e
		}
	}
	if e = checkSchemaPlan(ctx, tx, steps, false); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
