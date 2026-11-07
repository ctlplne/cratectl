// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
)

func requirementSelectorMod(selector, selected string) []byte {
	return []byte("module " + selector + "\ngo 1.16\nrequire " + selected + " v1.1.0\n")
}

func TestGoRequirementGuardFixtureRetainsLowerInputAndExaminesLegacySelectedVersion(t *testing.T) {
	lower := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/intake", Version: "v1.0.0"}
	higher := gomodule.Coordinate{Module: lower.Module, Version: "v1.1.0"}
	selector := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/selector", Version: "v1.0.0"}
	main := []byte("module owned/main\ngo 1.27.0\nrequire (\n" + lower.Module + " " + lower.Version + "\n" + selector.Module + " " + selector.Version + "\n)\n")
	for _, scenario := range []struct {
		name string
		mod  []byte
		want int
	}{{"mixed-legacy", requirementSelectorMod(selector.Module, lower.Module), 3}, {"original-modern-control", bytes.Replace(requirementSelectorMod(selector.Module, lower.Module), []byte("go 1.16\n"), []byte("go 1.26.0\n"), 1), 2}} {
		t.Run(scenario.name, func(t *testing.T) {
			corpus := map[gomodule.Coordinate][]byte{lower: []byte("module " + lower.Module + "\ngo 1.26.0\n"), higher: []byte("module " + higher.Module + "\ngo 1.26.0\n"), selector: scenario.mod}
			graph, err := gomodule.ResolveRequirements(context.Background(), main, func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
				raw, ok := corpus[c]
				if ctx.Err() != nil || !ok || int64(len(raw)) > maximum {
					return nil, gomodule.ErrGraphLimit
				}
				return raw, nil
			}, gomodule.DefaultGraphLimits())
			if err != nil || !graph.Pruned || len(graph.Inputs) != scenario.want || len(graph.BuildList) != 2 || graph.BuildList[0].Source != higher || graph.BuildList[1].Source != selector {
				t.Fatal("fixture traversal/selection changed", graph, err)
			}
			foundLower, foundHigher := false, false
			for _, input := range graph.Inputs {
				foundLower = foundLower || input.Source == lower
				foundHigher = foundHigher || input.Source == higher
			}
			if !foundLower || foundHigher != (scenario.want == 3) {
				t.Fatal("unselected input was lost or modern pruning was bypassed")
			}
		})
	}
}

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
