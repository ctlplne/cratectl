//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func requirementExportFixture(t *testing.T) (goIntakeFixture, GoRequirementExportRequest) {
	t.Helper()
	f, set := hostedExportSetFixture(t)
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/selector", Version: "v1.0.0"}
	mod := []byte("module " + c.Module + "\ngo 1.26.0\nrequire " + set.Entries[0].Module + " v1.1.0\n")
	result := f.bundleWithGoModAtPath(t, c, mod, "assets/owned.txt", "inert selecting module")
	ctx := context.Background()
	if _, err := f.s.PublishGoModule(ctx, f.i, set.Entries[0].Repository, result.GoModule.Objects, "requirement-selector-publication"); err != nil {
		t.Fatal(err)
	}
	for _, a := range result.GoModule.Objects {
		if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
			_, err := Decide(ctx, tx, f.i, set.Entries[0].Repository, a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f, GoRequirementExportRequest{Repository: set.Entries[0].Repository, MainGoMod: "module owned/main\ngo 1.27.0\nrequire (\n" + set.Entries[0].Module + " v1.0.0\n" + c.Module + " " + c.Version + "\n)\n", LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20}
}

func stageRequirementExport(t *testing.T, f goIntakeFixture, r GoRequirementExportRequest) (GoRequirementExportPlan, []blob.Object) {
	t.Helper()
	ctx := context.Background()
	reads := []GoRequirementRead{}
	_, err := gomodule.ResolveRequirements(ctx, []byte(r.MainGoMod), func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
		p, err := f.s.PlanGoExport(ctx, f.i, GoExportRequest{Repository: r.Repository, Module: c.Module, Version: c.Version, LifetimeSeconds: 60})
		if err != nil {
			return nil, err
		}
		o := p.Objects()[1]
		file, err := f.objects.OpenVerified(ctx, f.i.Tenant, o.Digest, o.Size)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
		if err == nil {
			reads = append(reads, GoRequirementRead{Plan: p, Mod: raw})
		}
		return raw, err
	}, gomodule.DefaultGraphLimits())
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.PlanGoRequirementExport(ctx, f.i, r, reads)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.sources) != 3 || len(p.manifest.Selection.Entries) != 2 {
		t.Fatal("fixture must retain a real lower unselected input", len(p.sources), len(p.manifest.Selection.Entries))
	}
	metadata, err := p.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	staged := []blob.Object{}
	for _, item := range metadata {
		o, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(item.Bytes), item.Object.Digest, item.Object.Size)
		if err != nil {
			t.Fatal(err)
		}
		staged = append(staged, o)
	}
	return p, staged
}

func requirementCounts(t *testing.T, f goIntakeFixture) [8]int {
	t.Helper()
	var out [8]int
	base := exportSetCounts(t, f)
	copy(out[:], base[:])
	if err := f.s.Tx(context.Background(), f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM cratectl.artifact_export_set_requirements),(SELECT count(*) FROM cratectl.artifact_export_set_requirement_sources)`).Scan(&out[6], &out[7])
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGoModuleRequirementExportAtomicGraphReplayOriginalEventAndAuditRetention(t *testing.T) {
	f, r := requirementExportFixture(t)
	ctx := context.Background()
	p, staged := stageRequirementExport(t, f, r)
	before := requirementCounts(t, f)
	res, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-original", 10)
	var v GoRequirementExportSession
	if err != nil || res.Status != 201 || json.Unmarshal(res.Body, &v) != nil || v.Manifest != p.Object() || v.SelectionManifest != p.selection.Object() || v.SourceCount != 3 || v.RootCount != 2 || v.DeliveryVerified {
		t.Fatal("atomic graph receipt", err)
	}
	after := requirementCounts(t, f)
	if after != [8]int{1, 2, 6, before[3] + 1, before[4] + 1, before[5] + 1, 1, 3} {
		t.Fatal("graph/session/roots/event/job/receipt not atomic", before, after)
	}
	var original crypt.JournalEvent
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sequence,payload,previous_hash,hash FROM cratectl.events WHERE sequence=$1`, v.CreatedSequence).Scan(&original.Sequence, &original.Payload, &original.PreviousHash, &original.Hash)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := BindGoRequirementExportManifest(p.Bytes(), f.i.Tenant, v.ID, original); err != nil {
		t.Fatal("actual original event not bound to staged graph", err)
	}
	for _, kind := range []string{"manifest", "selection", "main", "proof", "source-manifest", "source-mod"} {
		read, err := f.s.GoRequirementExportObject(ctx, f.i, v.ID, 1, 0, kind)
		if err != nil {
			t.Fatal("current graph metadata", kind, err)
		}
		file, err := f.objects.OpenVerified(ctx, f.i.Tenant, read.Object.Digest, read.Object.Size)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
	replay, found, err := f.s.ReplayGoRequirementExport(ctx, f.i, r, "graph-original")
	if err != nil || !found || !replay.Replay || !bytes.Equal(res.Body, replay.Body) || requirementCounts(t, f) != after {
		t.Fatal("lost response changed original receipt", err)
	}
	changed := r
	changed.MainGoMod += "// different original project\n"
	if _, _, err := f.s.ReplayGoRequirementExport(ctx, f.i, changed, "graph-original"); !errors.Is(err, ErrConflict) {
		t.Fatal("different project reused graph receipt", err)
	}
	if _, err := f.s.ChangeGoExportSet(ctx, f.i, v.ID, GoExportChange{Action: "cancel", ExpectedGeneration: 1, ManifestSHA256: v.SelectionManifest.Digest}, "graph-cancel"); err != nil {
		t.Fatal(err)
	}
	terminal, err := f.s.GoRequirementExport(ctx, f.i, v.ID)
	if err != nil || terminal.State != "cancelled" || terminal.PayloadPinsRetained || !terminal.ManifestRetained || terminal.Manifest != v.Manifest {
		t.Fatal("graph audit identity lost on shared cancellation", err)
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		digests := []string{p.selection.Objects()[0].Digest}
		for _, o := range staged {
			digests = append(digests, o.Digest)
		}
		for _, source := range p.manifest.Sources {
			digests = append(digests, source.Mod.Digest)
		}
		refs, err := currentDigestReferences(ctx, tx, digests)
		if err != nil {
			return err
		}
		if refs[digests[0]].Exports != 0 {
			t.Fatal("terminal selected ZIP pin not released")
		}
		for _, digest := range digests[1:] {
			if refs[digest].Exports < 1 {
				t.Fatal("immutable graph original no longer retained")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other := f.i
	other.Tenant, other.CredentialHash = "other-requirement-tenant", ""
	if _, err := f.s.GoRequirementExport(ctx, other, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant graph exposed", err)
	}
	if err := f.s.Tx(ctx, other, false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.artifact_export_set_requirements)+(SELECT count(*) FROM cratectl.artifact_export_set_requirement_sources)`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("graph/source RLS boundary exposed tenant data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleRequirementExportUnselectedInputFencesCreationLegacyDeliveryAndRenewal(t *testing.T) {
	for _, when := range []string{"before-creation", "after-creation"} {
		t.Run(when, func(t *testing.T) {
			f, r := requirementExportFixture(t)
			ctx := context.Background()
			p, staged := stageRequirementExport(t, f, r)
			var v GoRequirementExportSession
			if when == "after-creation" {
				res, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-current", 10)
				if err != nil || json.Unmarshal(res.Body, &v) != nil {
					t.Fatal(err)
				}
			}
			lower := p.sources[0].manifest
			if lower.Version != "v1.0.0" || lower.Module != p.sources[1].manifest.Module {
				t.Fatal("fixture lower input ordering changed")
			}
			decide := func(value string) {
				t.Helper()
				if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					_, err := Decide(ctx, tx, f.i, lower.Repository, lower.Artifacts[0].Path, lower.Artifacts[0].Digest, value)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			decide("denied")
			before := requirementCounts(t, f)
			if _, err := f.s.PlanGoExportSet(ctx, f.i, p.selection.request); err != nil {
				t.Fatal("control: selected higher roots remain allowed", err)
			}
			if when == "before-creation" {
				if _, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-current", 10); !errors.Is(err, ErrDenied) || requirementCounts(t, f) != before {
					t.Fatal("denied unselected input committed partial graph", err)
				}
			} else {
				for _, kind := range []string{"manifest", "zip", "mod", "info"} {
					if _, err := f.s.GoExportSetObject(ctx, f.i, v.ID, 1, 0, kind); !errors.Is(err, ErrDenied) {
						t.Fatal("legacy set route bypassed lower input denial", kind, err)
					}
				}
				if _, err := f.s.GoRequirementExportObject(ctx, f.i, v.ID, 1, 0, "main"); !errors.Is(err, ErrDenied) {
					t.Fatal("graph metadata bypassed lower input denial", err)
				}
				for _, action := range []string{"renew", "acknowledge"} {
					lifetime := 0
					if action == "renew" {
						lifetime = 60
					}
					if _, err := f.s.ChangeGoExportSet(ctx, f.i, v.ID, GoExportChange{Action: action, ExpectedGeneration: 1, LifetimeSeconds: lifetime, ManifestSHA256: v.SelectionManifest.Digest}, "graph-denied-"+action); !errors.Is(err, ErrDenied) || requirementCounts(t, f) != before {
						t.Fatal("denied graph renewal/ack committed", action, err)
					}
				}
			}
			decide("allowed")
			// A changed allowed decision is not the original immutable evidence.
			if when == "before-creation" {
				if _, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-current", 10); !errors.Is(err, ErrGoExportSetChanged) {
					t.Fatal("later allowance silently refreshed creation", err)
				}
			} else if _, err := f.s.GoExportSetObject(ctx, f.i, v.ID, 1, 0, "zip"); !errors.Is(err, ErrGoExportSetChanged) {
				t.Fatal("later allowance silently refreshed graph delivery", err)
			}
		})
	}
}

func TestGoModuleRequirementExportQueueQuotaAndMissingStageRollbackAndConcurrentReplay(t *testing.T) {
	f, r := requirementExportFixture(t)
	ctx := context.Background()
	p, staged := stageRequirementExport(t, f, r)
	before := requirementCounts(t, f)
	if _, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged[:len(staged)-1], "graph-missing-stage", 10); !errors.Is(err, ErrGoRequirementExport) || requirementCounts(t, f) != before {
		t.Fatal("missing metadata stage created partial graph", err)
	}
	if _, err := f.s.SetQueuePolicy(ctx, f.i, "", "", QueuePolicy{Queue: "events", Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
		t.Fatal(err)
	}
	before = requirementCounts(t, f)
	if _, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-full-queue", 10); !errors.Is(err, ErrQueueFull) || requirementCounts(t, f) != before {
		t.Fatal("queue failure committed partial graph", err)
	}
	if _, err := f.s.SetQueuePolicy(ctx, f.i, "", "", QueuePolicy{Queue: "events", Capacity: 1024, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
		t.Fatal(err)
	}
	createGoExportSet(t, f, p.selection.request, "graph-shared-quota")
	before = requirementCounts(t, f)
	if _, err := f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-quota", 1); !errors.Is(err, ErrGoExportLimit) || requirementCounts(t, f) != before {
		t.Fatal("graph escaped shared active quota", err)
	}
	var results [2]Result
	var failures [2]error
	var wg sync.WaitGroup
	for n := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[n], failures[n] = f.s.CommitGoRequirementExport(ctx, f.i, p, staged, "graph-concurrent", 10)
		}()
	}
	wg.Wait()
	if failures[0] != nil || failures[1] != nil || !bytes.Equal(results[0].Body, results[1].Body) || results[0].Replay == results[1].Replay {
		t.Fatal("concurrent creation did not coalesce to exact original", failures)
	}
	after := requirementCounts(t, f)
	if after != [8]int{before[0] + 1, before[1] + 2, before[2] + 6, before[3] + 1, before[4] + 1, before[5] + 1, 1, 3} {
		t.Fatal("concurrent graph duplicated durable effects", before, after)
	}
}
