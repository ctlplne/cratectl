//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func exportExpiryWorker(t *testing.T, f goIntakeFixture, tenant string) WorkerIdentity {
	t.Helper()
	token, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := Provision(context.Background(), f.d.OwnerDSN, tenant, "export-expiry", "worker", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	w, err := f.s.AuthenticateWorker(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// Owned timestamp aging exercises a due row; it is not a real clock-shift claim.
func ageGoExport(t *testing.T, f goIntakeFixture, id string) {
	t.Helper()
	ctx := context.Background()
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
	if _, err := tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, f.i.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour',max_expires_at=clock_timestamp()+interval '21 hours' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleExportWorkerExpiryQueueRollbackReplicasAndReferenceSafety(t *testing.T) {
	f, req := hostedExportFixture(t)
	ctx := context.Background()
	p, due := createGoExport(t, f, req, "worker-due")
	_, active := createGoExport(t, f, req, "worker-still-active")
	w := exportExpiryWorker(t, f, f.i.Tenant)
	ageGoExport(t, f, due.ID)
	setCapacity := func(capacity int) {
		t.Helper()
		if _, err := f.s.SetQueuePolicy(ctx, f.i, "", "", QueuePolicy{Queue: "events", Capacity: capacity, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
			t.Fatal(err)
		}
	}
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
	setCapacity(1)
	before := exportCounts(t, f, "worker-due")
	if _, err := f.s.ExpireNextGoExport(ctx, w); !errors.Is(err, ErrQueueFull) {
		t.Fatal("expiry released roots without projection capacity", err)
	}
	if after := exportCounts(t, f, "worker-due"); after != before || refs() != 2 {
		t.Fatal("queue failure changed durable expiry or roots", before, after)
	}
	items, _, err := f.s.GoExports(ctx, f.i, 0, 100)
	if err != nil || len(items) != 2 || items[0].State != "expired_unreconciled" || items[0].Generation != 1 || !items[0].PayloadPinsRetained {
		t.Fatal("failed worker expiry became terminal", err)
	}
	setCapacity(1024)
	before = exportCounts(t, f, "worker-due")
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := f.s.ExpireNextGoExport(ctx, w)
			if err == nil && (v.ID != due.ID || v.Generation != 2 || v.State != "expired" || v.PayloadPinsRetained || !v.ManifestRetained || v.DeliveryVerified || v.Manifest != due.Manifest) {
				err = ErrGoExportChanged
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	succeeded, empty := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrNotFound) {
			empty++
		} else {
			t.Fatal("replica expiry", err)
		}
	}
	after := exportCounts(t, f, "worker-due")
	if succeeded != 1 || empty != 1 || after[2] != before[2]+1 || after[3] != before[3]+1 || after[4] != before[4] || refs() != 1 {
		t.Fatal("expiry duplicated event/job or released another export root", succeeded, empty, before, after)
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var payload []byte
		if err := tx.QueryRow(ctx, `SELECT e.payload FROM cratectl.events e JOIN cratectl.artifact_exports x ON x.change_sequence=e.sequence WHERE x.id=$1`, due.ID).Scan(&payload); err != nil {
			return err
		}
		var event struct {
			Actor string          `json:"actor"`
			Kind  string          `json:"kind"`
			Data  GoExportSession `json:"data"`
		}
		if json.Unmarshal(payload, &event) != nil || event.Actor != w.Actor || event.Kind != "go.export.changed" || event.Data.ID != due.ID || event.Data.State != "expired" {
			t.Fatal("worker transition lacks original journal attribution")
		}
		v, err := goExportSessionInTx(ctx, tx, f.i, active.ID)
		if err == nil && (v.State != "open" || v.Generation != 1 || !v.PayloadPinsRetained) {
			t.Fatal("worker changed an active session")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ExpireNextGoExport(ctx, w); !errors.Is(err, ErrNotFound) {
		t.Fatal("lost response caused a second expiration", err)
	}
}

func TestGoModuleExportWorkerExpiryRequiresCurrentPurposeAndTenant(t *testing.T) {
	f, req := hostedExportFixture(t)
	ctx := context.Background()
	_, due := createGoExport(t, f, req, "credential-due")
	ageGoExport(t, f, due.ID)
	w := exportExpiryWorker(t, f, f.i.Tenant)
	other := exportExpiryWorker(t, f, "other-export-tenant")
	before := exportCounts(t, f, "credential-due")
	for _, invalid := range []WorkerIdentity{{}, {Tenant: f.i.Tenant, Actor: f.i.Actor, CredentialHash: f.i.CredentialHash}, {Tenant: "other-export-tenant", Actor: w.Actor, CredentialHash: w.CredentialHash}} {
		if _, err := f.s.ExpireNextGoExport(ctx, invalid); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("wrong credential purpose/tenant admitted expiry", err)
		}
	}
	if _, err := f.s.ExpireNextGoExport(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatal("other tenant discovered due export", err)
	}
	owner, err := pgx.Connect(ctx, f.d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if _, err := owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, w.CredentialHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ExpireNextGoExport(ctx, w); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revoked worker expired an export", err)
	}
	if after := exportCounts(t, f, "credential-due"); after != before {
		t.Fatal("rejected worker changed expiry/event/job/receipt", before, after)
	}
	if _, err := f.s.ChangeRepositoryState(ctx, f.i, req.Repository, "", "", RepositoryStateRequest{Action: "remove", ExpectedRevision: 0, Reason: "Owned source retirement before expiry"}, 10); err != nil {
		t.Fatal(err)
	}
	current := exportExpiryWorker(t, f, f.i.Tenant)
	if _, err := owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, f.i.CredentialHash); err != nil {
		t.Fatal(err)
	}
	if v, err := f.s.ExpireNextGoExport(ctx, current); err != nil || v.ID != due.ID || v.State != "expired" || v.PayloadPinsRetained || v.Manifest != due.Manifest {
		t.Fatal("retired source or revoked creator stranded a due lease despite current worker authority", err)
	}
}
