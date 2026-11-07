//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Create only a new project-owned role/database in the owned CI cluster. Role
// cleanup is registered before testdb.New so its database is dropped first.
func legacyNonsuperOwnerDatabase(t *testing.T) testdb.Database {
	t.Helper()
	ctx := context.Background()
	base := os.Getenv("CRATECTL_OWNER_DSN")
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() != "127.0.0.1" || u.Port() != "35432" {
		t.Fatal("owned native PostgreSQL URI required")
	}
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal("connect owned migration role fixture")
	}
	defer admin.Close(ctx)
	secret, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	role := "cratectl-migration-owner-" + crypt.Digest([]byte(secret))[:12]
	var statement string
	if err = admin.QueryRow(ctx, `SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD %L',$1::text,$2::text)`, role, secret).Scan(&statement); err != nil {
		t.Fatal("prepare owned migration role")
	}
	if _, err = admin.Exec(ctx, statement); err != nil {
		t.Fatal("create owned migration role", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := pgx.Connect(cleanup, base)
		if err != nil {
			t.Error("connect owned role cleanup")
			return
		}
		defer c.Close(cleanup)
		if _, err = c.Exec(cleanup, `DROP ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Error("drop owned migration role", err)
		}
	})
	d := testdb.New(t)
	target, err := url.Parse(d.OwnerDSN)
	if err != nil || !strings.HasPrefix(strings.TrimPrefix(target.Path, "/"), "cratectl_init_") {
		t.Fatal("owned disposable migration database required")
	}
	if _, err = admin.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{strings.TrimPrefix(target.Path, "/")}.Sanitize()+` OWNER TO `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal("assign owned migration database", err)
	}
	target.User = url.UserPassword(role, secret)
	d.OwnerDSN = target.String()
	return d
}

// Declared schema-13 SQL fixtures, not inferred execution by an old binary.
// No current retrieval row survives. The original repository is removed and
// its source epoch differs, so a current-cache/current-key-only backfill loses it.
func seedLegacyChecksumSchema13(t *testing.T, d testdb.Database) map[string]Event {
	t.Helper()
	ctx := context.Background()
	steps := currentMigrations()
	if err := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:13]); err != nil {
		t.Fatal("owned prior schema13", err)
	}
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal("connect prior schema owner")
	}
	defer owner.Close(ctx)
	var super, bypass bool
	if err = owner.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass); err != nil || super || bypass {
		t.Fatal("fixture must use nonsuperuser non-BYPASS migration owner", err)
	}
	log := checksumTimelineFixture(t)
	coordinate, err := gomodule.Canonical(log.Module, "v1.0.0")
	if err != nil {
		t.Fatal("prior-schema fixture requires a canonical coordinate", err)
	}
	a := log.authority()
	settings, err := json.Marshal(RepositorySettings{GoChecksumAuthority: &a, Cache: CacheSettings{RequireChecksum: true}})
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]Event{}
	for _, tenant := range []string{"legacy-team", "another-team"} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO cratectl.tenants(tenant)VALUES($1)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,source_revision,settings)VALUES($1,'old-source','go','proxy',3,$2),($1,'selected','go','proxy',0,$2)`, tenant, settings); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO cratectl.repository_lifecycle(tenant,repository,state,revision,reason,actor,change_sequence)VALUES($1,'old-source','removed',1,'retained old incident','operator',1)`, tenant); err != nil {
			t.Fatal(err)
		}
		if err = appendEventIntent(ctx, tx, Identity{Tenant: tenant, Actor: "operator", Role: "admin"}, "proxy.retrieval.failed", map[string]any{"repository": "old-source", "path": coordinate.Prefix() + ".zip", "generation": 2, "source_revision": 0, "failure": "upstream_checksum_fork"}, false); err != nil {
			t.Fatal(err)
		}
		var event Event
		if err = tx.QueryRow(ctx, `SELECT sequence,payload,previous_hash,hash FROM cratectl.events WHERE sequence=1`).Scan(&event.Sequence, &event.Payload, &event.PreviousHash, &event.Hash); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		before[tenant] = event
	}
	return before
}

func assertLegacyMigrationPolicies(t *testing.T, d testdb.Database, version int) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal("connect policy inspection")
	}
	defer c.Close(ctx)
	var temporary int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM pg_policy WHERE polname='go_checksum_legacy_migration_owner'`).Scan(&temporary); err != nil || temporary != 0 {
		t.Fatal("migration-only policy survived commit/rollback", temporary, err)
	}
	tables := []string{"events", "go_checksum_failures", "go_checksum_forks"}
	if version >= 14 {
		tables = append(tables, "go_checksum_legacy_incidents", "go_checksum_legacy_reviews")
	}
	if version >= 15 {
		tables = append(tables, "artifact_exports", "artifact_export_items")
	}
	if version >= 17 {
		tables = append(tables, "artifact_export_sets", "artifact_export_set_roots", "artifact_export_set_items")
	}
	if version >= 18 {
		tables = append(tables, "artifact_export_set_requirements", "artifact_export_set_requirement_sources")
	}
	for _, table := range tables {
		var forced bool
		var policies int
		if err = c.QueryRow(ctx, `SELECT c.relrowsecurity AND c.relforcerowsecurity,(SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl' AND c.relname=$1`, table).Scan(&forced, &policies); err != nil || !forced || policies != 1 {
			t.Fatal("migration changed forced tenant isolation", table, err, forced, policies)
		}
	}
}

func TestGoModuleLegacyChecksumBackfillPreservesEveryTenantAndOriginalJournalUnderNonsuperOwner(t *testing.T) {
	d := legacyNonsuperOwnerDatabase(t)
	before := seedLegacyChecksumSchema13(t, d)
	ctx := context.Background()
	plan, err := MigrationPlan(ctx, d.OwnerDSN)
	if err != nil || len(plan.Applied) != 13 || !reflect.DeepEqual(plan.Pending, []int{14, 15, 16, 17, 18}) {
		t.Fatal("prior schema13 plan", err)
	}
	if err = Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal("nonsuper cross-tenant backfill", err)
	}
	assertLegacyMigrationPolicies(t, d, 18)
	after, err := MigrationPlan(ctx, d.OwnerDSN)
	if err != nil || len(after.Applied) != 18 || !reflect.DeepEqual(after.Applied[:13], plan.Applied) || !after.SafetyValid {
		t.Fatal("backfill changed old receipts or isolation", err)
	}
	s, err := Open(ctx, d.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Pool.Close()
	for tenant, event := range before {
		i := Identity{Tenant: tenant, Actor: "operator", Role: "admin"}
		page, more, err := s.GoChecksumLegacyIncidentPage(ctx, i, 0, 1, "")
		if err != nil || len(page) != 1 || more || page[0].EventHash != event.Hash {
			t.Fatal("owner-only backfill missed or leaked a tenant", tenant, err)
		}
		evidence, err := s.GoChecksumLegacyIncidentEvidence(ctx, i, event.Sequence)
		if err != nil || !reflect.DeepEqual(evidence.OriginalEvent, event) || evidence.Classification != "unattributed_fork_label" {
			t.Fatal("backfill rewrote original journal bytes or invented proof", err)
		}
		state, err := s.GoChecksumState(ctx, i, "selected", 0)
		if err != nil || state.Blocked || !state.LegacyReviewRequired || state.Checkpoint.Revision != 0 {
			t.Fatal("current key/source assumed old attribution", err)
		}
	}
	// Identical external key and old coordinates do not share decisions across
	// tenants. The old unprovisioned fixture identity is an explicit internal
	// actor; current HTTP credential enforcement has a separate real-DB journey.
	reviewer := Identity{Tenant: "legacy-team", Actor: "operator", Role: "admin"}
	state, err := s.GoChecksumState(ctx, reviewer, "selected", 0)
	if err != nil {
		t.Fatal(err)
	}
	input := GoChecksumLegacyReviewRequest{AcceptUnattributedHistory: true, IncidentHash: before[reviewer.Tenant].Hash, KeyDigest: state.Checkpoint.KeyDigest, CheckpointSHA256: state.CheckpointSHA256, ReviewReferenceSHA256: crypt.Digest([]byte("one tenant external trust decision")), Reason: "Explicit external trust review limited to this tenant"}
	if _, err = s.ReviewGoChecksumLegacyIncident(ctx, reviewer, "selected", 1, "tenant-scoped-legacy-review", crypt.Digest([]byte("one tenant review")), input); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"legacy-team", "another-team"} {
		state, err := s.GoChecksumState(ctx, Identity{Tenant: tenant, Actor: "operator", Role: "admin"}, "selected", 0)
		if err != nil || state.Blocked || state.LegacyReviewRequired != (tenant == "another-team") {
			t.Fatal("review crossed tenant boundary or invented key proof", tenant, err)
		}
	}
	if err = Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal("backfill no-op replay", err)
	}
	assertLegacyMigrationPolicies(t, d, 18)
	if err = checkOldLegacyRuntime(ctx, d, 13); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted schema17", err)
	}
}

func checkOldLegacyRuntime(ctx context.Context, d testdb.Database, version int) error {
	c, err := pgx.Connect(ctx, d.RuntimeDSN)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	return checkSchemaPlan(ctx, c, currentMigrations()[:version], true)
}

func TestGoModuleLegacyChecksumInterruptedBackfillRollsBackPoliciesRowsAndReceipt(t *testing.T) {
	d := legacyNonsuperOwnerDatabase(t)
	before := seedLegacyChecksumSchema13(t, d)
	ctx := context.Background()
	steps := currentMigrations()
	last := 13 // The frozen backfill is step14, even after later steps are appended.
	if steps[last].Version != 14 {
		t.Fatal("backfill step identity changed")
	}
	needle := "DROP POLICY go_checksum_legacy_migration_owner ON cratectl.events;"
	probe := `DO $owned_rollback$ DECLARE who text; n bigint; BEGIN
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl' AND c.relname IN ('events','go_checksum_failures','go_checksum_forks','go_checksum_legacy_incidents','go_checksum_legacy_reviews') AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)) THEN RAISE EXCEPTION 'owned fixture observed unforced tenant data'; END IF;
 IF (SELECT count(*) FROM pg_policy WHERE polname='go_checksum_legacy_migration_owner')<>4 THEN RAISE EXCEPTION 'owned fixture migration policy missing'; END IF;
 FOREACH who IN ARRAY ARRAY['legacy-team','another-team'] LOOP
  PERFORM set_config('cratectl.tenant',who,true);
  SELECT count(*) INTO n FROM cratectl.go_checksum_legacy_incidents WHERE tenant=who;
  IF n<>1 THEN RAISE EXCEPTION 'owned fixture tenant was not backfilled'; END IF;
 END LOOP;
 RAISE EXCEPTION 'owned rollback probe after backfill';
 END $owned_rollback$;`
	if strings.Count(steps[last].SQL, needle) != 1 {
		t.Fatal("owned rollback injection point changed")
	}
	steps[last].SQL = strings.Replace(steps[last].SQL, needle, probe+needle, 1)
	err := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "P0001" || pgerr.Message != "owned rollback probe after backfill" {
		t.Fatal("controlled migration did not reach post-backfill rollback probe", err)
	}
	assertLegacyMigrationPolicies(t, d, 13)
	plan, err := MigrationPlan(ctx, d.OwnerDSN)
	if err != nil || len(plan.Applied) != 13 || !reflect.DeepEqual(plan.Pending, []int{14, 15, 16, 17, 18}) || !plan.SafetyValid {
		t.Fatal("interruption left a partial receipt or unsafe schema", err)
	}
	c, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal("connect rollback inspection")
	}
	defer c.Close(ctx)
	var absent bool
	if err = c.QueryRow(ctx, `SELECT to_regclass('cratectl.go_checksum_legacy_incidents')IS NULL AND to_regclass('cratectl.go_checksum_legacy_reviews')IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("interruption left partial incident tables", err)
	}
	for tenant, event := range before {
		tx, err := c.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		var payload, hash string
		if err = tx.QueryRow(ctx, `SELECT payload,hash FROM cratectl.events WHERE sequence=1`).Scan(&payload, &hash); err != nil || payload != event.Payload || hash != event.Hash {
			t.Fatal("rollback changed original journal", err)
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err = Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal("valid migration cannot resume after rolled-back fixture fault", err)
	}
	assertLegacyMigrationPolicies(t, d, 18)
}

func TestGoModuleLegacyChecksumBackfillDistinguishesTypedForkFromOrphanedAttribution(t *testing.T) {
	d := legacyNonsuperOwnerDatabase(t)
	seedLegacyChecksumSchema13(t, d)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	log := checksumTimelineFixture(t)
	coordinate, err := gomodule.Canonical(log.Module, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(log.Key, log.One)
	if err != nil {
		t.Fatal(err)
	}
	// This is a declared schema-13 SQL fixture using independently checked
	// original public proof. It is not a claim that an old binary executed it.
	report := checksumFailureReport(t, log, log.Fork, log.One)
	classification, err := classifyGoChecksumFailure(ctx, report, log.Key, log.One, log.One)
	if err != nil || classification != "fork" {
		t.Fatal("fixture must contain a real authenticated fork", err)
	}
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('cratectl.tenant','legacy-team',true)`); err != nil {
		t.Fatal(err)
	}
	record := GoChecksumFailureRecord{Profile: GoChecksumFailureEvidenceProfile, Tenant: "legacy-team", Repository: "selected", RootPath: coordinate.Prefix() + ".zip", Generation: 1, KeyDigest: initial.KeyDigest, CurrentCheckpoint: log.One, Classification: "fork", Report: report}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	digest := crypt.Digest(raw)
	if _, err = tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_failures(tenant,repository,root_path,source_revision,generation,key_digest,expected_checkpoint_revision,classification,evidence,evidence_digest,change_sequence)VALUES('legacy-team','selected',$1,0,1,$2,0,'fork',$3,$4,2)`, record.RootPath, initial.KeyDigest, raw, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_forks(tenant,key_digest,repository,root_path,source_revision,generation,change_sequence)VALUES('legacy-team',$1,'selected',$2,0,1,2)`, initial.KeyDigest, record.RootPath); err != nil {
		t.Fatal(err)
	}
	i := Identity{Tenant: "legacy-team", Actor: "operator", Role: "admin"}
	for _, eventDigest := range []string{digest, strings.Repeat("0", 64)} {
		if err = appendEventIntent(ctx, tx, i, "proxy.retrieval.failed", map[string]any{"repository": "selected", "path": record.RootPath, "source_revision": 0, "generation": 1, "failure": "upstream_checksum_fork", "go_checksum_failure_digest": eventDigest}, false); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, d.OwnerDSN); err != nil {
		t.Fatal(err)
	}
	assertLegacyMigrationPolicies(t, d, 18)
	s, err := Open(ctx, d.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Pool.Close()
	items, more, err := s.GoChecksumLegacyIncidentPage(ctx, i, 0, 100, initial.KeyDigest)
	if err != nil || more || len(items) != 2 || items[0].Sequence != 1 || items[1].Sequence != 3 {
		t.Fatal("typed original fork or unmatched digest misclassified", err, items)
	}
	state, err := s.GoChecksumState(ctx, i, "selected", 0)
	if err != nil || !state.Blocked || !state.LegacyReviewRequired {
		t.Fatal("typed fork or unattributed label lost", err)
	}
	input := GoChecksumLegacyReviewRequest{AcceptUnattributedHistory: true, IncidentHash: items[0].EventHash, KeyDigest: initial.KeyDigest, CheckpointSHA256: state.CheckpointSHA256, ReviewReferenceSHA256: crypt.Digest([]byte("external review")), Reason: "cannot clear authenticated fork"}
	if _, err = s.ReviewGoChecksumLegacyIncident(ctx, i, "selected", 1, "typed-fork-review", crypt.Digest([]byte("typed fork review")), input); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("legacy review cleared retained typed fork", err)
	}
}

func TestGoModuleLegacyChecksumDamagedOriginalHistoryRefusesMigrationAtomically(t *testing.T) {
	d := legacyNonsuperOwnerDatabase(t)
	seedLegacyChecksumSchema13(t, d)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('cratectl.tenant','legacy-team',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cratectl.events SET hash=$1 WHERE tenant='legacy-team' AND sequence=1`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, d.OwnerDSN); !errors.Is(err, ErrGoChecksumLegacyChanged) {
		t.Fatal("damaged original event link accepted as migrated incident", err)
	}
	assertLegacyMigrationPolicies(t, d, 13)
	plan, err := MigrationPlan(ctx, d.OwnerDSN)
	if err != nil || len(plan.Applied) != 13 || !reflect.DeepEqual(plan.Pending, []int{14, 15, 16, 17, 18}) || !plan.SafetyValid {
		t.Fatal("failed integrity check left partial schema14 receipt", err)
	}
	var absent bool
	if err = c.QueryRow(ctx, `SELECT to_regclass('cratectl.go_checksum_legacy_incidents')IS NULL AND to_regclass('cratectl.go_checksum_legacy_reviews')IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("damaged-history rollback left partial incident tables", err)
	}
}
