//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleExportBackgroundWorkerReconcilesWithoutAdministratorRead(t *testing.T) {
	s, token, admin, req, d := exportServerFixture(t)
	raw, _ := json.Marshal(req)
	w := goHTTP(t, s, token, "POST", "/api/v1/go/exports", raw, "Idempotency-Key", "background-export")
	var created store.GoExportSession
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		t.Fatal("create background expiry fixture", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, admin.Tenant); err != nil {
		t.Fatal(err)
	}
	// Declared owned timestamp aging, not a real clock-shift qualification.
	if _, err := tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour',max_expires_at=clock_timestamp()+interval '21 hours' WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	list := func() store.GoExportSession {
		t.Helper()
		// List is deliberately read-only; GET /ID would itself reconcile expiry.
		v, _, err := s.DB.GoExports(ctx, admin, 0, 100)
		if err != nil || len(v) != 1 {
			t.Fatal("read-only export list", err)
		}
		return v[0]
	}
	if v := list(); v.State != "expired_unreconciled" || !v.PayloadPinsRetained {
		t.Fatal("fixture expired without a terminal transaction")
	}
	stop := repairWorker(t, s, d) // Actual existing tenant worker, all queue lanes.
	defer stop()
	for {
		v := list()
		if v.State == "expired" {
			if v.Generation != 2 || v.PayloadPinsRetained || !v.ManifestRetained || v.DeliveryVerified || v.Manifest != created.Manifest || v.CreatedSequence != created.CreatedSequence {
				t.Fatal("background expiry changed immutable identity or trust")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("background worker did not expire due export")
		case <-time.After(20 * time.Millisecond):
		}
	}
	stop()
	var count int
	if err := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.events e JOIN cratectl.artifact_exports x ON x.change_sequence=e.sequence JOIN cratectl.jobs j ON j.sequence=e.sequence AND j.task='event' WHERE x.id=$1 AND e.payload::jsonb->>'kind'='go.export.changed' AND e.payload::jsonb->>'actor'='repair-worker'`, created.ID).Scan(&count)
	}); err != nil || count != 1 {
		t.Fatal("background expiry lacks exactly one worker-attributed journal/job intent", count, err)
	}
}
