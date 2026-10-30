//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/testdb"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func sourceSettings(name string) RepositorySettings {
	return RepositorySettings{Upstream: &upstream.Config{URL: "https://" + name + ".example/", Networks: []string{"0.0.0.0/0", "::/0"}}, Cache: CacheSettings{FreshSeconds: 3600, StaleSeconds: 3600}}
}

func TestSourceConfigurationEpochFencesCacheValidatorsAndABARollback(t *testing.T) {
	_, db, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	settings := sourceSettings("first")
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, i, Repository{Name: "source", Format: "generic", Mode: "proxy", Settings: settings})
	}); e != nil {
		t.Fatal(e)
	}
	lease, e := db.AcquireRetrieval(ctx, i, "source", "cached", "first-fill", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 200, Object: &blob.Object{Digest: strings.Repeat("a", 64), Size: 3}, ETag: `"same-validator"`, Modified: "Thu, 29 Oct 2026 12:00:00 GMT", FreshSeconds: 3600, StaleSeconds: 3600}); e != nil {
		t.Fatal(e)
	}
	pending, e := db.AcquireRetrieval(ctx, i, "source", "pending", "old-worker", true)
	if e != nil {
		t.Fatal(e)
	}
	next := sourceSettings("second")
	input := ConfigurationRequest{ExpectedRevision: 0, Settings: &next, Reason: "switch approved source", DryRun: true}
	if _, e = db.ChangeConfiguration(ctx, i, "source", "", "", input, 10); e != nil {
		t.Fatal(e)
	}
	if r, e := db.Repository(ctx, i, "source"); e != nil || r.SourceRevision != 0 {
		t.Fatal("preview changed configuration", r, e)
	}
	input.DryRun = false
	first, e := db.ChangeConfiguration(ctx, i, "source", "source-change", "source-fingerprint", input, 10)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.CompleteRetrieval(ctx, i, pending, RetrievalResult{Status: 404}); !errors.Is(e, ErrSourceChanged) {
		t.Fatal("old fill committed", e)
	}
	if _, e = db.Retrieval(ctx, i, "source", "cached", 0); !errors.Is(e, ErrSourceChanged) {
		t.Fatal("stale request snapshot read cache", e)
	}
	r, e := db.Retrieval(ctx, i, "source", "cached", 1)
	if e != nil || r.Fresh() || r.StalePermitted() || !r.SourceChanged {
		t.Fatal("old cache remained fresh", r, e)
	}
	if _, e = db.Artifact(ctx, i, "source", "cached"); !errors.Is(e, ErrSourceChanged) {
		t.Fatal("old bytes admitted", e)
	}
	fresh, e := db.AcquireRetrievalWithLease(ctx, i, "source", "cached", "new-worker", true, 32, time.Minute, 1)
	if e != nil {
		t.Fatal(e)
	}
	if fresh.SourceRevision != 1 || fresh.ETag != "" || fresh.Modified != "" || fresh.SourceStale != 0 || fresh.StaleUntil.After(fresh.Now) {
		t.Fatal("old validators/stale window crossed epoch", fresh)
	}
	if e = db.CompleteRetrieval(ctx, i, fresh, RetrievalResult{Status: 304}); !errors.Is(e, ErrSourceChanged) {
		t.Fatal("unconditional 304 borrowed old source bytes", e)
	}
	if _, e = db.ChangeConfiguration(ctx, i, "source", "", "", ConfigurationRequest{ExpectedRevision: 1, Settings: &settings, Reason: "roll back source"}, 10); e != nil {
		t.Fatal(e)
	}
	if e = db.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 304}); !errors.Is(e, ErrSourceChanged) {
		t.Fatal("ABA revived original fill", e)
	}
	replay, e := db.ChangeConfiguration(ctx, i, "source", "source-change", "source-fingerprint", input, 10)
	if e != nil || !replay.Replay || string(first.Body) != string(replay.Body) {
		t.Fatal("configuration replay", e)
	}
	current, e := db.Configuration(ctx, i, "source")
	if e != nil || current.SourceRevision != 2 || current.Settings.Upstream.URL != settings.Upstream.URL {
		t.Fatal("replay changed current configuration", current, e)
	}
	history, e := db.ConfigurationHistory(ctx, i, "source", 0, 10)
	if e != nil || len(history) != 2 || history[0].PreviousSettings.Upstream.URL != settings.Upstream.URL || history[1].Revision != 2 {
		t.Fatal("configuration history", history, e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.repository_configurations SET reason='tampered' WHERE repository='source'`)
		return e
	}); e == nil {
		t.Fatal("runtime modified immutable configuration history")
	}
}

func TestSourceConfigurationCurrentLocatorRevisionAndOutboxAtomicity(t *testing.T) {
	_, db, owner, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	settings := sourceSettings("first")
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, i, Repository{Name: "python-source", Format: "pypi", Mode: "proxy", Settings: settings})
	}); e != nil {
		t.Fatal(e)
	}
	key := strings.Repeat("b", 64)
	catalog := PythonCatalog{Name: "project", Files: map[string]string{"project-1.whl": key}}
	raw, _ := json.Marshal(catalog)
	lease, e := db.AcquireRetrieval(ctx, i, "python-source", "pypi-catalog/project", "catalog-owner", true)
	if e != nil {
		t.Fatal(e)
	}
	result := RetrievalResult{Status: 200, Object: &blob.Object{Digest: strings.Repeat("c", 64), Size: int64(len(raw))}, Metadata: raw, MediaType: PythonCatalogMedia, FreshSeconds: 3600, NativeCatalog: &NativeCatalogPublication{Name: "project", Entries: catalog.Files, Sources: []NativeSource{{Key: key, Format: "pypi", Name: "project", Coordinate: "project-1.whl", Version: "1", URL: "https://first.example/project-1.whl", Integrity: "sha256:" + strings.Repeat("d", 64), Metadata: json.RawMessage(`{}`)}}}}
	if e = db.CompleteRetrieval(ctx, i, lease, result); e != nil {
		t.Fatal(e)
	}
	if _, e = db.NativeSource(ctx, i, "python-source", key, "pypi"); e != nil {
		t.Fatal(e)
	}
	next := sourceSettings("first")
	next.Upstream.CredentialRef = "rotated"
	next.Upstream.Authentication = "bearer"
	input := ConfigurationRequest{ExpectedRevision: 0, Settings: &next, Reason: "new source"}
	if _, e = db.ChangeConfiguration(ctx, i, "python-source", "", "", input, 10); e != nil {
		t.Fatal(e)
	}
	if _, e = db.NativeSource(ctx, i, "python-source", key, "pypi"); !errors.Is(e, ErrSourceChanged) {
		t.Fatal("old native locator admitted", e)
	}
	lease, e = db.AcquireRetrieval(ctx, i, "python-source", "pypi-catalog/project", "current-catalog", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.CompleteRetrieval(ctx, i, lease, result); e != nil {
		t.Fatal(e)
	}
	if _, e = db.NativeSource(ctx, i, "python-source", key, "pypi", 1); e != nil {
		t.Fatal("current immutable locator receipt missing", e)
	}
	if e = db.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var count int
		e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.native_sources WHERE repository='python-source' AND key=$1`, key).Scan(&count)
		if count != 2 {
			t.Error("old locator receipt overwritten", count)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(ctx, `CREATE FUNCTION cratectl_private.configuration_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned configuration outbox fault'; END $$;CREATE TRIGGER configuration_outbox_fault BEFORE INSERT ON cratectl.jobs FOR EACH ROW EXECUTE FUNCTION cratectl_private.configuration_outbox_fault()`); e != nil {
		t.Fatal(e)
	}
	input.ExpectedRevision = 1
	if _, e = db.ChangeConfiguration(ctx, i, "python-source", "rollback-config", "rollback-fingerprint", input, 10); e == nil {
		t.Fatal("outbox fault accepted")
	}
	current, e := db.Configuration(ctx, i, "python-source")
	if e != nil || current.SourceRevision != 1 {
		t.Fatal("epoch survived failed outbox", current, e)
	}
	history, e := db.ConfigurationHistory(ctx, i, "python-source", 0, 10)
	if e != nil || len(history) != 1 {
		t.Fatal("history survived failed outbox", history, e)
	}
}

func TestSourceConfigurationMigrationPreservesV3AndForcedRLS(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	steps := currentMigrations()
	if e := migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:3]); e != nil {
		t.Fatal(e)
	}
	before, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || len(before.Applied) != 3 || len(before.Pending) != len(steps)-3 || before.Pending[0] != 4 || !before.SafetyValid {
		t.Fatal(before, e)
	}
	if e = migrateSteps(ctx, d.OwnerDSN, MigrationOptions{}, steps[:4]); e != nil {
		t.Fatal(e)
	}
	after, e := MigrationPlan(ctx, d.OwnerDSN)
	if e != nil || after.DatabaseState != "pending" || len(after.Applied) != 4 || len(after.Pending) != 1 || after.Pending[0] != 5 || !after.SafetyValid {
		t.Fatal(after, e)
	}
	for n := range before.Applied {
		if before.Applied[n] != after.Applied[n] {
			t.Fatal("changed a frozen receipt")
		}
	}
	runtime, e := pgx.Connect(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	if e = checkSchemaPlan(ctx, runtime, steps[:3], true); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("old runtime admitted source schema", e)
	}
	var count int
	if e = runtime.QueryRow(ctx, `SELECT count(*) FROM cratectl.repository_configurations`).Scan(&count); e != nil || count != 0 {
		t.Fatal("unscoped history visible", count, e)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `ALTER TABLE cratectl.repository_configurations NO FORCE ROW LEVEL SECURITY`); e != nil {
		t.Fatal(e)
	}
	if _, e = MigrationPlan(ctx, d.OwnerDSN); !errors.Is(e, ErrSchemaIncompatible) {
		t.Fatal("unsafe source history accepted", e)
	}
}

func TestSourceConfigurationPopulatedHistoryIsTenantScopedAndAppendOnly(t *testing.T) {
	d, db, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	otherToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = Provision(ctx, d.OwnerDSN, "configuration-other", "operator", "admin", otherToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	other, e := db.Authenticate(ctx, otherToken)
	if e != nil {
		t.Fatal(e)
	}
	settings := sourceSettings("private")
	for _, identity := range []Identity{i, other} {
		if e = db.Tx(ctx, identity, true, func(tx pgx.Tx) error {
			return CreateRepository(ctx, tx, identity, Repository{Name: "collision", Format: "generic", Mode: "proxy", Settings: settings})
		}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.ChangeConfiguration(ctx, i, "collision", "", "", ConfigurationRequest{Settings: &settings, Reason: "private source change"}, 10); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		identity Identity
		want     int
	}{{i, 1}, {other, 0}} {
		if e = db.Tx(ctx, test.identity, false, func(tx pgx.Tx) error {
			var count int
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.repository_configurations`).Scan(&count); e != nil {
				return e
			}
			if count != test.want {
				t.Errorf("cross-tenant configuration history: got %d, want %d", count, test.want)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	var unscoped int
	if e = db.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.repository_configurations`).Scan(&unscoped); e != nil || unscoped != 0 {
		t.Fatal("unscoped populated history visible", unscoped, e)
	}
	for _, sql := range []string{
		`UPDATE cratectl.repository_configurations SET reason='tampered' WHERE repository='collision'`,
		`DELETE FROM cratectl.repository_configurations WHERE repository='collision'`,
		`INSERT INTO cratectl.repository_configurations(tenant,repository,revision,previous_revision,previous_settings,settings,reason,actor,change_sequence) VALUES('configuration-other','collision',1,0,'{}','{}','cross tenant','operator',1)`,
	} {
		e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, sql); return e })
		var denied *pgconn.PgError
		if !errors.As(e, &denied) || denied.Code != "42501" {
			t.Fatal("expected PostgreSQL permission/RLS rejection", e)
		}
	}
	if history, e := db.ConfigurationHistory(ctx, i, "collision", 0, 10); e != nil || len(history) != 1 || history[0].Reason != "private source change" {
		t.Fatal("history changed after denied operations", history, e)
	}
	if history, e := db.ConfigurationHistory(ctx, other, "collision", 0, 10); e != nil || len(history) != 0 {
		t.Fatal("cross-tenant API history visible", history, e)
	}
}
