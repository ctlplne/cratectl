//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

// This owner-inserted occupancy fixture measures the query and pin accounting,
// not API creation throughput or independently bound manifests for every row.
// It preserves a valid event hash chain and clones only owned inert object IDs.
func populateExportIndexFixture(t *testing.T, f goIntakeFixture, seed GoExportSession, tenant string, terminal, future, due int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, f.d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if tenant != f.i.Tenant {
		for _, q := range []string{`INSERT INTO cratectl.tenants(tenant) VALUES($1) ON CONFLICT DO NOTHING`, `INSERT INTO cratectl.repositories(tenant,name,format) VALUES($1,'exported','go')`} {
			if _, err := tx.Exec(ctx, q, tenant); err != nil {
				t.Fatal(err)
			}
		}
	}
	var sequence int64
	var previous string
	err = tx.QueryRow(ctx, `SELECT sequence,hash FROM cratectl.events WHERE tenant=$1 ORDER BY sequence DESC LIMIT 1`, tenant).Scan(&sequence, &previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	const batch = 1024
	for first := 0; first < terminal+future+due; first += batch {
		count := min(batch, terminal+future+due-first)
		events := make([][]any, 0, count)
		exports := make([][]any, 0, count)
		for n := first; n < first+count; n++ {
			sequence++
			id := crypt.Digest([]byte(fmt.Sprintf("owned-index-fixture/%s/%d", tenant, n)))
			payload, err := json.Marshal(map[string]any{"tenant": tenant, "actor": "owned-fixture", "sequence": sequence, "kind": "owned.export.index.fixture", "data": map[string]any{"id": id}, "time": now.UTC().Format(time.RFC3339Nano)})
			if err != nil {
				t.Fatal(err)
			}
			hash := crypt.Digest(append([]byte(previous+"\n"), payload...))
			events = append(events, []any{tenant, sequence, string(payload), previous, hash})
			previous = hash
			state := "open"
			expires := now.Add(2 * time.Hour)
			if n < terminal {
				state = "expired"
				expires = now.Add(-time.Hour)
			} else if n >= terminal+future {
				expires = now.Add(-time.Hour)
			} else if n%2 == 0 {
				state = "acknowledged"
			}
			exports = append(exports, []any{tenant, id, seed.Repository, seed.SourceRevision, seed.Module, seed.Version, seed.Actor, seed.Manifest.Digest, seed.Manifest.Size, state, int64(1), sequence, sequence, now.Add(-2 * time.Hour), now, expires, now.Add(20 * time.Hour)})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cratectl", "events"}, []string{"tenant", "sequence", "payload", "previous_hash", "hash"}, pgx.CopyFromRows(events)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cratectl", "artifact_exports"}, []string{"tenant", "id", "repository", "source_revision", "module", "version", "actor", "manifest_digest", "manifest_size", "state", "generation", "created_sequence", "change_sequence", "created_at", "changed_at", "expires_at", "max_expires_at"}, pgx.CopyFromRows(exports)); err != nil {
			t.Fatal(err)
		}
	}
	if tenant == f.i.Tenant {
		if _, err := tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_items(tenant,export_id,ordinal,path,digest,size) SELECT x.tenant,x.id,i.ordinal,i.path,i.digest,i.size FROM cratectl.artifact_exports x CROSS JOIN cratectl.artifact_export_items i WHERE i.tenant=$2 AND x.tenant=$2 AND i.export_id=$1 AND x.id<>$1`, seed.ID, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `ANALYZE cratectl.artifact_exports`); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleExportExpiryIndexBoundsIdleAndDueWorkThroughRetainedHistory(t *testing.T) {
	f, req := hostedExportFixture(t)
	req.LifetimeSeconds = 3600
	ctx := context.Background()
	p, active := createGoExport(t, f, req, "indexed-active")
	acknowledged, err := f.s.ChangeGoExport(ctx, f.i, active.ID, GoExportChange{Action: "acknowledge", ExpectedGeneration: active.Generation, ManifestSHA256: active.Manifest.Digest}, "indexed-ack")
	if err != nil || acknowledged.Status != 200 || json.Unmarshal(acknowledged.Body, &active) != nil || active.State != "acknowledged" {
		t.Fatal("owned acknowledged seed", err)
	}
	worker := exportExpiryWorker(t, f, f.i.Tenant)
	populateExportIndexFixture(t, f, active, f.i.Tenant, 32768, 4096, 0)
	populateExportIndexFixture(t, f, active, "other-index-tenant", 0, 0, 1024)
	initial, err := f.s.GoExport(ctx, f.i, active.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := exportCounts(t, f, "indexed-active")
	refs := func() int64 {
		t.Helper()
		var n int64
		if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
			v, err := currentDigestReferences(ctx, tx, []string{p.Objects()[0].Digest})
			n = v[p.Objects()[0].Digest].Exports
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if refs() != 4097 {
		t.Fatal("owned active roots not retained")
	}
	explain := func(label string) {
		t.Helper()
		if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
			var safe bool
			if err := tx.QueryRow(ctx, `SELECT NOT r.rolsuper AND NOT r.rolbypassrls AND r.oid<>c.relowner FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE r.rolname=current_user AND n.nspname='cratectl' AND c.relname='artifact_exports'`).Scan(&safe); err != nil {
				return err
			}
			if !safe {
				t.Fatal("plan was not measured as nonowner nonsuperuser without BYPASSRLS")
			}
			var raw []byte
			if err := tx.QueryRow(ctx, `EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) `+nextGoExportExpirySQL).Scan(&raw); err != nil {
				return err
			}
			var plans []struct {
				Plan map[string]any `json:"Plan"`
			}
			if err := json.Unmarshal(raw, &plans); err != nil {
				return err
			}
			if len(plans) != 1 {
				t.Fatal("missing actual query plan")
			}
			index := false
			var walk func(map[string]any)
			walk = func(node map[string]any) {
				kind, _ := node["Node Type"].(string)
				if kind == "Sort" || kind == "Seq Scan" || kind == "Bitmap Heap Scan" {
					t.Fatalf("%s scanned or sorted retained history: %s", label, kind)
				}
				if node["Index Name"] == "artifact_exports_due" {
					index = true
				}
				if n, _ := node["Actual Rows"].(float64); n > 1 {
					t.Fatalf("%s examined unbounded output rows: %.0f", label, n)
				}
				if n, _ := node["Rows Removed by Filter"].(float64); n > 0 {
					t.Fatalf("%s scanned unwanted rows: %.0f", label, n)
				}
				for _, child := range rangeAny(node["Plans"]) {
					walk(child.(map[string]any))
				}
			}
			walk(plans[0].Plan)
			hit, _ := plans[0].Plan["Shared Hit Blocks"].(float64)
			read, _ := plans[0].Plan["Shared Read Blocks"].(float64)
			if !index || hit+read > 64 {
				t.Fatalf("%s missing bounded partial index: index=%v buffers=%.0f", label, index, hit+read)
			}
			t.Logf("%s: terminal=32768 future=4096 other-tenant-due=1024 partial-index=true returned=1 buffers=%.0f", label, hit+read)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	explain("idle")
	for range 3 {
		if _, err := f.s.ExpireNextGoExport(ctx, worker); !errors.Is(err, ErrNotFound) {
			t.Fatal("idle visit changed a future lease", err)
		}
	}
	if exportCounts(t, f, "indexed-active") != before || refs() != 4097 {
		t.Fatal("idle visit changed rows, journal, jobs, receipt or roots")
	}
	current, err := f.s.GoExport(ctx, f.i, active.ID)
	current.ServerTime = initial.ServerTime
	if err != nil || current != initial {
		t.Fatal("idle visit changed original session", err)
	}
	ageGoExport(t, f, active.ID)
	explain("due")
	expired, err := f.s.ExpireNextGoExport(ctx, worker)
	if err != nil || expired.ID != active.ID || expired.Generation != active.Generation+1 || expired.State != "expired" || expired.PayloadPinsRetained {
		t.Fatal("indexed due row not reconciled", err)
	}
	after := exportCounts(t, f, "indexed-active")
	if after[0] != before[0] || after[1] != before[1] || after[2] != before[2]+1 || after[3] != before[3]+1 || after[4] != before[4] || refs() != 4096 {
		t.Fatal("indexed expiry changed unrelated history or roots", before, after)
	}
	if _, err := f.s.ExpireNextGoExport(ctx, worker); !errors.Is(err, ErrNotFound) {
		t.Fatal("indexed expiry duplicated transition", err)
	}
	owner, err := pgx.Connect(ctx, f.d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if _, err := owner.Exec(ctx, `SELECT set_config('cratectl.tenant','other-index-tenant',false)`); err != nil {
		t.Fatal(err)
	}
	var other int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM cratectl.artifact_exports WHERE tenant='other-index-tenant' AND state='open' AND generation=1`).Scan(&other); err != nil || other != 1024 {
		t.Fatal("expiry changed other tenant rows", err, other)
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.artifact_exports WHERE tenant='other-index-tenant'`).Scan(&n)
		if n != 0 {
			t.Fatal("other tenant visible to runtime")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func rangeAny(value any) []any {
	if value == nil {
		return nil
	}
	return value.([]any)
}
