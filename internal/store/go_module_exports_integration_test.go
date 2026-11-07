//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func hostedExportFixture(t *testing.T) (goIntakeFixture, GoExportRequest) {
	t.Helper()
	f := newGoIntakeFixture(t)
	ctx := context.Background()
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, f.i, Repository{Name: "exported", Format: "go", RequireReview: true, Access: "restricted"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PublishGoModule(ctx, f.i, "exported", f.result.GoModule.Objects, "hosted-export-publication"); err != nil {
		t.Fatal(err)
	}
	for _, a := range f.result.GoModule.Objects {
		if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
			_, err := Decide(ctx, tx, f.i, "exported", a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := ValidateGoModuleArtifact(f.result.GoModule.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	return f, GoExportRequest{Repository: "exported", Module: m.Module, Version: m.Version, LifetimeSeconds: 60}
}

func stageGoExport(t *testing.T, f goIntakeFixture, r GoExportRequest) (GoExportPlan, blob.Object) {
	t.Helper()
	p, err := f.s.PlanGoExport(context.Background(), f.i, r)
	if err != nil {
		t.Fatal(err)
	}
	o, err := f.objects.Put(context.Background(), f.i.Tenant, bytes.NewReader(p.Bytes()), p.Object().Digest, p.Object().Size)
	if err != nil {
		t.Fatal(err)
	}
	return p, o
}
func createGoExport(t *testing.T, f goIntakeFixture, r GoExportRequest, key string) (GoExportPlan, GoExportSession) {
	t.Helper()
	p, o := stageGoExport(t, f, r)
	res, err := f.s.CommitGoExport(context.Background(), f.i, p, o, key, 10)
	var v GoExportSession
	if err != nil || res.Status != 201 || json.Unmarshal(res.Body, &v) != nil || v.DeliveryVerified || !v.PayloadPinsRetained || !v.ManifestRetained {
		t.Fatal("durable snapshot commit", err)
	}
	return p, v
}
func exportCounts(t *testing.T, f goIntakeFixture, key string) [5]int {
	t.Helper()
	var out [5]int
	if err := f.s.Tx(context.Background(), f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM cratectl.artifact_exports),(SELECT count(*) FROM cratectl.artifact_export_items),(SELECT count(*) FROM cratectl.events),(SELECT count(*) FROM cratectl.jobs),(SELECT count(*) FROM cratectl.mutations WHERE actor=$1 AND key=$2)`, f.i.Actor, key).Scan(&out[0], &out[1], &out[2], &out[3], &out[4])
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGoModuleExportImmutableSnapshotStageReplayAndOriginalJournal(t *testing.T) {
	f, req := hostedExportFixture(t)
	ctx := context.Background()
	p, o := stageGoExport(t, f, req)
	// Unrelated later events must not silently replace the captured head, or
	// unnecessarily prevent commit of unchanged exact byte/policy identity.
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		return appendEventIntent(ctx, tx, f.i, "owned.export.unrelated", map[string]bool{"unrelated": true}, false)
	}); err != nil {
		t.Fatal(err)
	}
	res, err := f.s.CommitGoExport(ctx, f.i, p, o, "export-lost-reply", 10)
	if err != nil {
		t.Fatal(err)
	}
	var v GoExportSession
	if json.Unmarshal(res.Body, &v) != nil || v.State != "open" {
		t.Fatal("created receipt")
	}
	replay, ok, err := f.s.ReplayGoExport(ctx, f.i, req, "export-lost-reply")
	if err != nil || !ok || !replay.Replay || !bytes.Equal(replay.Body, res.Body) {
		t.Fatal("lost response did not recover original durable receipt", err)
	}
	again, err := f.s.CommitGoExport(ctx, f.i, p, o, "export-lost-reply", 10)
	if err != nil || !again.Replay || !bytes.Equal(again.Body, res.Body) {
		t.Fatal("duplicate commit changed receipt", err)
	}
	if counts := exportCounts(t, f, "export-lost-reply"); counts[0] != 1 || counts[1] != 3 || counts[4] != 1 {
		t.Fatal("partial or duplicated durable export", counts)
	}
	var original crypt.JournalEvent
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sequence,payload,previous_hash,hash FROM cratectl.events WHERE sequence=$1`, v.CreatedSequence).Scan(&original.Sequence, &original.Payload, &original.PreviousHash, &original.Hash)
	}); err != nil {
		t.Fatal(err)
	}
	event := crypt.JournalEvent{Sequence: original.Sequence, Payload: original.Payload, PreviousHash: original.PreviousHash, Hash: original.Hash}
	m, err := BindGoExportManifest(p.Bytes(), f.i.Tenant, req.Repository, v.ID, p.Coordinate(), event)
	if err != nil || m.ObservedJournal != p.manifest.ObservedJournal || m.CurrentRegistryAdmission || m.ChecksumAuthority || m.DependencyClosure {
		t.Fatal("original export event detached from exact policy/byte manifest", err)
	}
	for _, kind := range []string{"manifest", "zip", "mod", "info"} {
		view, err := f.s.GoExportObject(ctx, f.i, v.ID, 1, kind)
		if err != nil {
			t.Fatal(kind, err)
		}
		file, err := f.objects.OpenVerified(ctx, f.i.Tenant, view.Object.Digest, view.Object.Size)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var jobs int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.jobs WHERE sequence=$1`, v.CreatedSequence).Scan(&jobs)
		if err == nil && jobs < 1 {
			t.Fatal("export event committed without durable job intent")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rows, more, err := f.s.GoExports(ctx, f.i, 0, 1)
	if err != nil || more || len(rows) != 1 || rows[0].ID != v.ID {
		t.Fatal("durable resume inventory", err)
	}
}

func TestGoModuleExportRevalidatesPolicyBytesEpochAndStagedHandle(t *testing.T) {
	for _, scenario := range []string{"deny", "decision-version", "source-epoch", "changed-byte", "oversized-metadata", "wrong-staged-object", "wrong-actor", "wrong-tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f, req := hostedExportFixture(t)
			ctx := context.Background()
			p, o := stageGoExport(t, f, req)
			if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
				a := f.result.GoModule.Objects[0]
				switch scenario {
				case "deny":
					_, err := Decide(ctx, tx, f.i, req.Repository, a.Path, a.Digest, "denied")
					return err
				case "decision-version":
					_, err := Decide(ctx, tx, f.i, req.Repository, a.Path, a.Digest, "allowed")
					return err
				case "source-epoch":
					_, err := tx.Exec(ctx, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name=$1`, req.Repository)
					return err
				case "changed-byte":
					_, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET digest=$1 WHERE repository=$2 AND path=$3`, crypt.Digest([]byte("other owned identity")), req.Repository, a.Path)
					return err
				case "oversized-metadata":
					_, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=jsonb_build_object('padding',repeat('x',5000)) WHERE repository=$1 AND path=$2`, req.Repository, a.Path)
					return err
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "wrong-staged-object":
				o.Size++
			case "wrong-actor":
				p.actor = "other"
			case "wrong-tenant":
				p.tenant = "other"
			}
			before := exportCounts(t, f, "stale-plan")
			if _, err := f.s.CommitGoExport(ctx, f.i, p, o, "stale-plan", 10); err == nil {
				t.Fatal("stale or forged snapshot admitted", scenario)
			}
			if after := exportCounts(t, f, "stale-plan"); after != before {
				t.Fatal("rejected export left a partial transition", before, after)
			}
		})
	}
}

func TestGoModuleExportQueueRollbackConcurrentReplayAndRetainedBudget(t *testing.T) {
	t.Run("queue-full", func(t *testing.T) {
		f, req := hostedExportFixture(t)
		ctx := context.Background()
		p, o := stageGoExport(t, f, req)
		if _, err := f.s.SetQueuePolicy(ctx, f.i, "export-queue-budget", "export-queue-budget", QueuePolicy{Queue: "events", Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
			t.Fatal(err)
		}
		before := exportCounts(t, f, "queue-lost")
		if _, err := f.s.CommitGoExport(ctx, f.i, p, o, "queue-lost", 10); !errors.Is(err, ErrQueueFull) {
			t.Fatal("saturated intent accepted", err)
		}
		if after := exportCounts(t, f, "queue-lost"); after != before {
			t.Fatal("queue failure committed pins/event/job/receipt", before, after)
		}
		file, err := f.objects.OpenVerified(ctx, f.i.Tenant, o.Digest, o.Size)
		if err != nil {
			t.Fatal("unreferenced staged bytes were deleted after uncertain admission", err)
		}
		file.Close()
	})
	t.Run("concurrent-replay-and-budget", func(t *testing.T) {
		f, req := hostedExportFixture(t)
		ctx := context.Background()
		p, o := stageGoExport(t, f, req)
		var wg sync.WaitGroup
		results := make(chan Result, 2)
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := f.s.CommitGoExport(ctx, f.i, p, o, "same-export", 1)
				results <- r
				errs <- err
			}()
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var first []byte
		replays := 0
		var session GoExportSession
		for r := range results {
			if r.Replay {
				replays++
			}
			if first == nil {
				first = r.Body
			}
			if !bytes.Equal(first, r.Body) {
				t.Fatal("concurrent receipts differ")
			}
			if json.Unmarshal(r.Body, &session) != nil {
				t.Fatal("session receipt")
			}
		}
		if replays != 1 {
			t.Fatal("concurrent create duplicated", replays)
		}
		p2, o2 := stageGoExport(t, f, req)
		if _, err := f.s.CommitGoExport(ctx, f.i, p2, o2, "over-budget", 1); !errors.Is(err, ErrGoExportLimit) {
			t.Fatal("retained session cap bypassed", err)
		}
		if _, err := f.s.ChangeGoExport(ctx, f.i, session.ID, GoExportChange{Action: "cancel", ExpectedGeneration: session.Generation, ManifestSHA256: session.Manifest.Digest}, "cancel-budget"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.CommitGoExport(ctx, f.i, p2, o2, "over-budget", 1); err != nil {
			t.Fatal("cancel did not release configured retained-session capacity", err)
		}
	})
}

func TestGoModuleExportCurrentPolicyRenewAcknowledgeCancelAndPins(t *testing.T) {
	f, req := hostedExportFixture(t)
	ctx := context.Background()
	p, v := createGoExport(t, f, req, "export-lifecycle")
	assertRefs := func(wantPayload int64) {
		t.Helper()
		if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
			refs, err := currentDigestReferences(ctx, tx, []string{v.Manifest.Digest, p.manifest.Artifacts[0].Digest})
			if err != nil {
				return err
			}
			if refs[v.Manifest.Digest].Exports != 1 || refs[p.manifest.Artifacts[0].Digest].Exports != wantPayload {
				t.Fatal("inventory lost durable export references", refs)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertRefs(1)
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		a := p.manifest.Artifacts[0]
		_, err := Decide(ctx, tx, f.i, req.Repository, a.Path, a.Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GoExportObject(ctx, f.i, v.ID, v.Generation, "manifest"); !errors.Is(err, ErrDenied) {
		t.Fatal("retained snapshot bypassed current denial", err)
	}
	assertRefs(1)
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		a := p.manifest.Artifacts[0]
		_, err := Decide(ctx, tx, f.i, req.Repository, a.Path, a.Digest, "allowed")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.GoExportObject(ctx, f.i, v.ID, 1, "manifest")
	if err != nil || view.Object != p.Object() {
		t.Fatal("resumed read rewrote historical policy", err)
	}
	change := GoExportChange{Action: "renew", ExpectedGeneration: 1, LifetimeSeconds: 3600, ManifestSHA256: v.Manifest.Digest}
	res, err := f.s.ChangeGoExport(ctx, f.i, v.ID, change, "renew-export")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.s.ChangeGoExport(ctx, f.i, v.ID, change, "renew-export")
	if err != nil || !replay.Replay || !bytes.Equal(res.Body, replay.Body) {
		t.Fatal("renew lost-response replay", err)
	}
	if _, err := f.s.GoExportObject(ctx, f.i, v.ID, 1, "zip"); !errors.Is(err, ErrGoExportChanged) {
		t.Fatal("old transfer generation survived renewal", err)
	}
	current, err := f.s.GoExport(ctx, f.i, v.ID)
	if err != nil || current.Generation != 2 || current.ExpiresAt.After(current.MaxExpiresAt) || !current.ExpiresAt.After(v.ExpiresAt) {
		t.Fatal("bounded renewal", err)
	}
	if _, err := f.s.ChangeGoExport(ctx, f.i, v.ID, GoExportChange{Action: "acknowledge", ExpectedGeneration: 2, ManifestSHA256: v.Manifest.Digest}, "ack-export"); err != nil {
		t.Fatal(err)
	}
	current, err = f.s.GoExport(ctx, f.i, v.ID)
	if err != nil || current.State != "acknowledged" || current.DeliveryVerified || !current.PayloadPinsRetained {
		t.Fatal("client acknowledgment invented verified delivery", err)
	}
	assertRefs(1)
	if _, err := f.s.ChangeGoExport(ctx, f.i, v.ID, GoExportChange{Action: "cancel", ExpectedGeneration: 3, ManifestSHA256: v.Manifest.Digest}, "cancel-export"); err != nil {
		t.Fatal(err)
	}
	assertRefs(0)
	if _, err := f.s.GoExportObject(ctx, f.i, v.ID, 4, "zip"); !errors.Is(err, ErrGoExportExpired) {
		t.Fatal("cancelled export reopened bytes", err)
	}
}

func TestGoModuleExportForcedRLSImmutableRuntimeAndDurableExpiry(t *testing.T) {
	f, req := hostedExportFixture(t)
	ctx := context.Background()
	_, v := createGoExport(t, f, req, "export-isolation")
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE cratectl.artifact_export_items SET digest=$1 WHERE export_id=$2`, crypt.Digest([]byte("forged")), v.ID)
		return err
	}); err == nil {
		t.Fatal("runtime rewrote immutable snapshot item")
	}
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET manifest_size=1 WHERE id=$1`, v.ID)
		return err
	}); err == nil {
		t.Fatal("runtime rewrote immutable manifest identity")
	}
	var outside int
	if err := f.s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.artifact_exports`).Scan(&outside); err != nil || outside != 0 {
		t.Fatal("omitted tenant setting exposed exports", outside, err)
	}
	token, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := Provision(ctx, f.d.OwnerDSN, "other-export-team", "operator", "admin", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other, err := f.s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GoExport(ctx, other, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant export identity leaked", err)
	}
	owner, err := pgx.Connect(ctx, f.d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	// Declared owned timestamp fault, not a real clock-shift claim. Wall-clock
	// expiry retains pins until its fenced journal/job transition commits.
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true)`, f.i.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour',max_expires_at=clock_timestamp()+interval '21 hours' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		refs, err := currentDigestReferences(ctx, tx, []string{f.result.GoModule.Objects[0].Digest})
		if err == nil && refs[f.result.GoModule.Objects[0].Digest].Exports != 1 {
			t.Fatal("unreconciled expiry released physical protection")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expired, err := f.s.GoExport(ctx, f.i, v.ID)
	if err != nil || expired.State != "expired" || expired.Generation != 2 || expired.PayloadPinsRetained || !expired.ManifestRetained {
		t.Fatal("expiry was not a durable terminal transition", err)
	}
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, v.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GoExportObject(ctx, f.i, v.ID, 2, "zip"); !errors.Is(err, ErrGoExportExpired) {
		t.Fatal("clock/expiry rewrite resurrected terminal export", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, f.i.CredentialHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GoExport(ctx, f.i, v.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("resume metadata survived credential revocation", err)
	}
}

func TestGoModuleExportSignedManifestNativeOfflineSDK(t *testing.T) {
	f, req := hostedExportFixture(t)
	ctx := context.Background()
	p, v := createGoExport(t, f, req, "export-native")
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		return appendEventIntent(ctx, tx, f.i, "owned.export.tail", map[string]bool{"later": true}, false)
	}); err != nil {
		t.Fatal(err)
	}
	head, err := f.s.JournalCheckpoint(ctx, f.i)
	if err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	q := JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 1}
	for {
		page, err := f.s.JournalPage(ctx, f.i, q)
		if err != nil || json.NewEncoder(&journal).Encode(page) != nil {
			t.Fatal(err)
		}
		if !page.More {
			break
		}
		q.After, q.AfterHash = page.NextAfter, page.NextHash
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	var files [3]string
	for n, kind := range []string{"zip", "mod", "info"} {
		view, err := f.s.GoExportObject(ctx, f.i, v.ID, v.Generation, kind)
		if err != nil {
			t.Fatal(err)
		}
		input, err := f.objects.OpenVerified(ctx, f.i.Tenant, view.Object.Digest, view.Object.Size)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(input, 4<<20))
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[n] = filepath.Join(private, "original."+kind)
		if err := os.WriteFile(files[n], raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	verifyNativeGoOffline(t, private, files, journal.Bytes(), head, v.CreatedSequence, req.Repository, req.Module, req.Version, nativeGoExportSnapshot{v.ID, p.Bytes()})
}
