//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func hostedExportSetFixture(t *testing.T) (goIntakeFixture, GoExportSetRequest) {
	t.Helper()
	f, one := hostedExportFixture(t)
	ctx := context.Background()
	coordinate := gomodule.Coordinate{Module: one.Module, Version: "v1.1.0"}
	second := f.bundleAt(t, coordinate, "second original inert bytes")
	if _, err := f.s.PublishGoModule(ctx, f.i, one.Repository, second.GoModule.Objects, "set-preview-second-publication"); err != nil {
		t.Fatal(err)
	}
	for _, a := range second.GoModule.Objects {
		if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
			_, err := Decide(ctx, tx, f.i, one.Repository, a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f, GoExportSetRequest{Entries: []GoExportSetEntry{{Repository: one.Repository, Module: one.Module, Version: one.Version, ExpectedSourceRevision: one.ExpectedSourceRevision}, {Repository: one.Repository, Module: coordinate.Module, Version: coordinate.Version}}, LifetimeSeconds: 60, MaxArtifactBytes: 1 << 30}
}

func TestGoModuleExportSetPlansEveryOriginalOrReturnsNoPartialMetadata(t *testing.T) {
	f, request := hostedExportSetFixture(t)
	ctx := context.Background()
	before := exportCounts(t, f, "set-preview-unused")
	plan, err := f.s.PlanGoExportSet(ctx, f.i, request)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseGoExportSetManifest(plan.Bytes())
	if err != nil || len(m.Entries) != 2 || len(plan.Objects()) != 6 || m.CurrentRegistryAdmission || m.ChecksumAuthority || m.DependencyClosure {
		t.Fatal("invalid original set preview", err)
	}
	for n, entry := range m.Entries {
		if entry.Module != request.Entries[n].Module || entry.Version != request.Entries[n].Version || entry.ObservedJournal != m.ObservedJournal || !entry.PreparedAt.Equal(m.PreparedAt) {
			t.Fatal("mixed metadata snapshot/order")
		}
		for _, a := range entry.Artifacts {
			file, err := f.objects.OpenVerified(ctx, f.i.Tenant, a.Digest, a.Size)
			if err != nil {
				t.Fatal("fixture needs actual original CAS bytes", err)
			}
			file.Close()
		}
	}
	exact := request
	exact.MaxArtifactBytes = m.DeclaredArtifactBytes
	if _, err := f.s.PlanGoExportSet(ctx, f.i, exact); err != nil {
		t.Fatal("exact byte budget refused", err)
	}
	for _, scenario := range []string{"late-source-epoch", "late-missing-root", "late-byte-budget", "wrong-tenant", "reader", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			r := request
			r.Entries = append([]GoExportSetEntry(nil), request.Entries...)
			i := f.i
			runContext, cancel := context.WithCancel(ctx)
			defer cancel()
			switch scenario {
			case "late-source-epoch":
				r.Entries[1].ExpectedSourceRevision = 99
			case "late-missing-root":
				r.Entries[1].Version = "v1.9.9"
			case "late-byte-budget":
				r.MaxArtifactBytes = m.DeclaredArtifactBytes - 1
			case "wrong-tenant":
				i.Tenant = "other-team"
			case "reader":
				i.Role = "reader"
			case "cancelled":
				cancel()
			}
			got, err := f.s.PlanGoExportSet(runContext, i, r)
			if err == nil || len(got.Bytes()) != 0 || len(got.Objects()) != 0 {
				t.Fatal("invalid later member exposed a partial preview", scenario, err)
			}
		})
	}
	if after := exportCounts(t, f, "set-preview-unused"); after != before {
		t.Fatal("read-only planning changed exports/items/journal/jobs/receipts", before, after)
	}
	// A late unassessed/denied member must not be reported as a complete set.
	second := m.Entries[1].Artifacts[0]
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := Decide(ctx, tx, f.i, request.Entries[1].Repository, second.Path, second.Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := f.s.PlanGoExportSet(ctx, f.i, request)
	if !errors.Is(err, ErrDenied) || len(got.Bytes()) != 0 {
		t.Fatal("denied later source escaped", err)
	}
}

func TestGoModuleExportSetUsesOneActualRepeatableReadSnapshot(t *testing.T) {
	f, request := hostedExportSetFixture(t)
	ctx := context.Background()
	initial, err := f.s.PlanGoExportSet(ctx, f.i, request)
	if err != nil {
		t.Fatal(err)
	}
	old, err := ParseGoExportSetManifest(initial.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	second := old.Entries[1].Artifacts[0]
	var captured GoExportSetPlan
	err = f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var isolation, readOnly string
		if err := tx.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SHOW transaction_read_only`).Scan(&readOnly); err != nil {
			return err
		}
		if isolation != "repeatable read" || readOnly != "on" {
			t.Fatal("snapshot transaction contract", isolation, readOnly)
		}
		// Establish and observe this transaction's actual old member view. A second
		// real connection then commits a denial before the batch helper reads it.
		repo, err := goExportAdmin(ctx, tx, f.i, request.Entries[0].Repository, true)
		if err != nil {
			return err
		}
		if _, err = goHostedExportArtifacts(ctx, tx, repo, gomodule.Coordinate{Module: request.Entries[0].Module, Version: request.Entries[0].Version}); err != nil {
			return err
		}
		_, err = f.s.Mutate(ctx, f.i, "set-preview-concurrent-deny", second.Digest, "artifact.decision", func(write pgx.Tx) (any, int, error) {
			v, err := Decide(ctx, write, f.i, request.Entries[1].Repository, second.Path, second.Digest, "denied")
			return v, 200, err
		})
		if err != nil {
			return err
		}
		captured, err = planGoExportSetInTx(ctx, tx, f.i, request)
		return err
	})
	if err != nil {
		t.Fatal("one admitted snapshot mixed a later committed policy", err)
	}
	common, err := ParseGoExportSetManifest(captured.Bytes())
	if err != nil || len(common.Entries) != 2 || common.ObservedJournal != old.ObservedJournal || common.Entries[1].Artifacts[0].Decision != "allowed" {
		t.Fatal("mixed journal/member view", err)
	}
	if latest, err := f.s.PlanGoExportSet(ctx, f.i, request); !errors.Is(err, ErrDenied) || len(latest.Bytes()) != 0 {
		t.Fatal("fresh admission ignored current committed denial", err)
	}
	// A consistent old preview is still unsigned/unverified and has no durable
	// references, session or approval grant. The concurrent mutation is the sole
	// event/receipt effect in this test; it must remain independently observable.
	counts := exportCounts(t, f, "set-preview-concurrent-deny")
	if counts[0] != 0 || counts[1] != 0 || counts[4] != 1 {
		t.Fatal("preview created durable references/receipt", counts)
	}
}
