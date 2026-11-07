// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"testing"
)

func TestGoRequirementExportPlanRejectsWrongOriginalBytesBeforeDatabase(t *testing.T) {
	m, raw, _, _ := goExportManifestFixture(t)
	i := Identity{Tenant: m.Tenant, Actor: "operator", Role: "admin"}
	request := GoRequirementExportRequest{Repository: m.Repository, MainGoMod: "module owned/main\ngo 1.27.0\n", LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20}
	one := GoExportRequest{Repository: m.Repository, Module: m.Module, Version: m.Version, LifetimeSeconds: 60}
	read := GoRequirementRead{Plan: GoExportPlan{tenant: i.Tenant, actor: i.Actor, request: one, manifest: m, raw: raw}, Mod: []byte("xx")}
	var unavailable *Store
	got, err := unavailable.PlanGoRequirementExport(context.Background(), i, request, []GoRequirementRead{read})
	if !errors.Is(err, ErrGoRequirementExport) || got.Bytes() != nil {
		t.Fatal("different original bytes reached the database or returned a plan", err)
	}
	if _, err := got.Metadata(); err == nil {
		t.Fatal("zero plan offered success-shaped metadata")
	}
}
