//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

func exportSetCounts(t *testing.T, f goIntakeFixture) [6]int {
	t.Helper()
	var out [6]int
	if err := f.s.Tx(context.Background(), f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM cratectl.artifact_export_sets),(SELECT count(*) FROM cratectl.artifact_export_set_roots),(SELECT count(*) FROM cratectl.artifact_export_set_items),(SELECT count(*) FROM cratectl.events),(SELECT count(*) FROM cratectl.jobs),(SELECT count(*) FROM cratectl.mutations)`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4], &out[5])
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
func createGoExportSet(t *testing.T, f goIntakeFixture, r GoExportSetRequest, key string) (GoExportSetPlan, GoExportSetSession, Result) {
	t.Helper()
	ctx := context.Background()
	p, err := f.s.PlanGoExportSet(ctx, f.i, r)
	if err != nil {
		t.Fatal(err)
	}
	o := p.Object()
	staged, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(p.Bytes()), o.Digest, o.Size)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.s.CommitGoExportSet(ctx, f.i, p, staged, key, 10)
	if err != nil {
		t.Fatal(err)
	}
	var v GoExportSetSession
	if json.Unmarshal(result.Body, &v) != nil || result.Status != 201 || v.RootCount != len(r.Entries) || !v.PayloadPinsRetained || !v.ManifestRetained || v.DeliveryVerified {
		t.Fatal("invalid complete session receipt")
	}
	return p, v, result
}
func TestGoModuleExportSetAtomicPinsReplayCurrentPolicyAndTerminalRelease(t *testing.T) {
	f, r := hostedExportSetFixture(t)
	ctx := context.Background()
	before := exportSetCounts(t, f)
	p, v, receipt := createGoExportSet(t, f, r, "set-create")
	after := exportSetCounts(t, f)
	if after != [6]int{1, 2, 6, before[3] + 1, before[4] + 1, before[5] + 1} {
		t.Fatal("set roots/journal/job/receipt did not commit together", before, after)
	}
	replay, found, err := f.s.ReplayGoExportSet(ctx, f.i, r, "set-create")
	if err != nil || !found || !replay.Replay || !bytes.Equal(receipt.Body, replay.Body) || exportSetCounts(t, f) != after {
		t.Fatal("byte-exact receipt replay", err)
	}
	for root := range 2 {
		for _, kind := range []string{"zip", "mod", "info"} {
			got, err := f.s.GoExportSetObject(ctx, f.i, v.ID, 1, root, kind)
			if err != nil {
				t.Fatal("current complete-set read", err)
			}
			file, err := f.objects.OpenVerified(ctx, f.i.Tenant, got.Object.Digest, got.Object.Size)
			if err != nil {
				t.Fatal(err)
			}
			file.Close()
		}
	}
	ack, err := f.s.ChangeGoExportSet(ctx, f.i, v.ID, GoExportChange{Action: "acknowledge", ExpectedGeneration: 1, ManifestSHA256: v.Manifest.Digest}, "set-ack")
	if err != nil {
		t.Fatal(err)
	}
	var acknowledged GoExportSetSession
	if json.Unmarshal(ack.Body, &acknowledged) != nil || acknowledged.Generation != 2 || acknowledged.State != "acknowledged" || !acknowledged.PayloadPinsRetained || acknowledged.DeliveryVerified {
		t.Fatal("acknowledgment claimed delivery or released pins")
	}
	if _, err := f.s.GoExportSetObject(ctx, f.i, v.ID, 1, 0, "zip"); !errors.Is(err, ErrGoExportSetChanged) {
		t.Fatal("stale generation served", err)
	}
	// A denied later root fences even the first root and common manifest.
	late := p.manifest.Entries[1]
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := Decide(ctx, tx, f.i, late.Repository, late.Artifacts[0].Path, late.Artifacts[0].Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"manifest", "zip"} {
		if _, err := f.s.GoExportSetObject(ctx, f.i, v.ID, 2, 0, kind); !errors.Is(err, ErrDenied) {
			t.Fatal("late denied member failed to fence complete set", kind, err)
		}
	}
	if _, err := f.s.ChangeGoExportSet(ctx, f.i, v.ID, GoExportChange{Action: "renew", ExpectedGeneration: 2, LifetimeSeconds: 3600, ManifestSHA256: v.Manifest.Digest}, "set-denied-renew"); !errors.Is(err, ErrDenied) {
		t.Fatal("denied set renewed", err)
	}
	cancelled, err := f.s.ChangeGoExportSet(ctx, f.i, v.ID, GoExportChange{Action: "cancel", ExpectedGeneration: 2, ManifestSHA256: v.Manifest.Digest}, "set-cancel")
	if err != nil {
		t.Fatal(err)
	}
	var terminal GoExportSetSession
	if json.Unmarshal(cancelled.Body, &terminal) != nil || terminal.State != "cancelled" || terminal.Generation != 3 || terminal.PayloadPinsRetained || !terminal.ManifestRetained {
		t.Fatal("cancel lost immutable identity/released incorrectly")
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		refs, err := currentDigestReferences(ctx, tx, []string{v.Manifest.Digest, p.Objects()[0].Digest})
		if err == nil && (refs[v.Manifest.Digest].Exports != 1 || refs[p.Objects()[0].Digest].Exports != 0) {
			t.Fatal("terminal set root accounting", refs)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if after := exportSetCounts(t, f); after[0] != 1 || after[1] != 2 || after[2] != 6 {
		t.Fatal("terminal transition erased historical rows", after)
	}
	other := f.i
	other.Tenant = "other-set-tenant"
	other.CredentialHash = "" // Declared internal identity to probe RLS itself, not another tenant credential.
	if _, err := f.s.GoExportSet(ctx, other, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant session exposed", err)
	}
	if _, err := f.s.GoExportSetObject(ctx, f.i, v.ID, 3, 0, "manifest"); !errors.Is(err, ErrGoExportExpired) {
		t.Fatal("terminal set delivered bytes", err)
	}
}
func TestGoModuleExportSetLateChangeQueueAndQuotaRollbackHaveNoPartialReferences(t *testing.T) {
	f, r := hostedExportSetFixture(t)
	ctx := context.Background()
	p, err := f.s.PlanGoExportSet(ctx, f.i, r)
	if err != nil {
		t.Fatal(err)
	}
	o := p.Object()
	staged, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(p.Bytes()), o.Digest, o.Size)
	if err != nil {
		t.Fatal(err)
	}
	capacity := func(n int) {
		t.Helper()
		if _, err := f.s.SetQueuePolicy(ctx, f.i, "", "", QueuePolicy{Queue: "events", Capacity: n, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
			t.Fatal(err)
		}
	}
	capacity(1)
	before := exportSetCounts(t, f)
	if _, err := f.s.CommitGoExportSet(ctx, f.i, p, staged, "set-queue-full", 10); !errors.Is(err, ErrQueueFull) {
		t.Fatal("creation escaped full event queue", err)
	}
	if exportSetCounts(t, f) != before {
		t.Fatal("queue failure committed partial set")
	}
	capacity(1024)
	// An existing legacy export consumes the same configured active-session quota.
	one := GoExportRequest{Repository: r.Entries[0].Repository, Module: r.Entries[0].Module, Version: r.Entries[0].Version, LifetimeSeconds: 60}
	createGoExport(t, f, one, "legacy-quota")
	before = exportSetCounts(t, f)
	if _, err := f.s.CommitGoExportSet(ctx, f.i, p, staged, "set-quota", 1); !errors.Is(err, ErrGoExportLimit) {
		t.Fatal("legacy session did not consume common quota", err)
	}
	if exportSetCounts(t, f) != before {
		t.Fatal("quota failure committed partial set")
	}
	late := p.manifest.Entries[1]
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := Decide(ctx, tx, f.i, late.Repository, late.Artifacts[0].Path, late.Artifacts[0].Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before = exportSetCounts(t, f)
	if _, err := f.s.CommitGoExportSet(ctx, f.i, p, staged, "set-late-deny", 10); !errors.Is(err, ErrDenied) {
		t.Fatal("stale later policy committed", err)
	}
	if exportSetCounts(t, f) != before {
		t.Fatal("late member failure left partial effects")
	}
}
func TestGoModuleExportSetWorkerExpiryQueueRollbackAndReplicaFence(t *testing.T) {
	f, r := hostedExportSetFixture(t)
	ctx := context.Background()
	p, v, _ := createGoExportSet(t, f, r, "set-worker-due")
	w := exportExpiryWorker(t, f, f.i.Tenant)
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
	if _, err = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, f.i.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cratectl.artifact_export_sets SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour',max_expires_at=clock_timestamp()+interval '21 hours' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	capacity := func(n int) {
		t.Helper()
		if _, err := f.s.SetQueuePolicy(ctx, f.i, "", "", QueuePolicy{Queue: "events", Capacity: n, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
			t.Fatal(err)
		}
	}
	capacity(1)
	before := exportSetCounts(t, f)
	if _, err := f.s.ExpireNextGoExportSet(ctx, w); !errors.Is(err, ErrQueueFull) {
		t.Fatal("expiry released references without queue intent", err)
	}
	if exportSetCounts(t, f) != before {
		t.Fatal("failed expiry changed rows")
	}
	capacity(1024)
	before = exportSetCounts(t, f)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			expired, err := f.s.ExpireNextGoExportSet(ctx, w)
			if err == nil && (expired.ID != v.ID || expired.Generation != 2 || expired.State != "expired" || expired.PayloadPinsRetained || !expired.ManifestRetained) {
				results <- errors.New("invalid terminal parent")
				return
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, missing := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrNotFound) {
			missing++
		} else {
			t.Fatal("replica expiry", err)
		}
	}
	if success != 1 || missing != 1 {
		t.Fatal("replicas duplicated expiry", success, missing)
	}
	after := exportSetCounts(t, f)
	if after[3] != before[3]+1 || after[4] != before[4]+1 || after[5] != before[5] {
		t.Fatal("expiry event/job not atomic", before, after)
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		refs, err := currentDigestReferences(ctx, tx, []string{p.Objects()[0].Digest, v.Manifest.Digest})
		if err == nil && (refs[p.Objects()[0].Digest].Exports != 0 || refs[v.Manifest.Digest].Exports != 1) {
			t.Fatal("expiry root accounting", refs)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	invalid := w
	invalid.CredentialHash = ""
	if _, err := f.s.ExpireNextGoExportSet(ctx, invalid); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("uncredentialed expiry admitted", err)
	}
}
