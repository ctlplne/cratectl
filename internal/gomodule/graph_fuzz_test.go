// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"context"
	"errors"
	"testing"
)

func FuzzRequirementGraph(f *testing.F) {
	f.Add([]byte("module owned/main\ngo 1.26.0\nrequire example.invalid/a v1.0.0\n"), []byte("module example.invalid/a\ngo 1.26.0\nrequire example.invalid/b v1.0.0\n"))
	f.Add([]byte("module owned/main\ngo 1.16\nrequire example.invalid/a v1.0.0\n"), []byte("module example.invalid/a\nrequire example.invalid/a v1.0.0\n"))
	f.Add([]byte("module owned/main\nreplace example.invalid/a => ../private\n"), []byte{})
	f.Fuzz(func(t *testing.T, main, dependency []byte) {
		if len(main) > 32<<10 || len(dependency) > 32<<10 {
			return
		}
		limits := GraphLimits{Modules: 16, Versions: 16, Requirements: 64, MetadataBytes: 64 << 10}
		loads := 0
		graph, err := ResolveRequirements(context.Background(), main, func(_ context.Context, c Coordinate, maximum int64) ([]byte, error) {
			loads++
			if loads > limits.Versions || maximum < 1 || maximum > MaxGoMod {
				t.Fatal("metadata work escaped the fixed budget")
			}
			if c.Module != "example.invalid/a" || c.Version != "v1.0.0" {
				return nil, errors.New("owned fuzz input is unavailable")
			}
			return dependency, nil
		}, limits)
		if err != nil {
			if graph != nil {
				t.Fatal("failed graph returned a partial result")
			}
			return
		}
		if graph == nil || graph.MetadataBytes > limits.MetadataBytes || len(graph.BuildList) > limits.Modules || len(graph.Inputs) > limits.Versions || graph.Requirements > limits.Requirements {
			t.Fatal("successful graph escaped the fixed budget")
		}
		for _, selected := range graph.BuildList {
			if _, err := Canonical(selected.Logical.Module, selected.Logical.Version); err != nil {
				t.Fatal("selected noncanonical module")
			}
			if _, err := Canonical(selected.Source.Module, selected.Source.Version); err != nil {
				t.Fatal("selected noncanonical source")
			}
		}
	})
}
