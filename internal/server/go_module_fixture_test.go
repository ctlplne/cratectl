// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

// Preserve the existing publication fixture's dependency and original directive.
// Explicit exports need not include its closure; requirement exports must.
func goPublicationFixture(t testing.TB, c gomodule.Coordinate, payload string) ([]byte, []byte) {
	t.Helper()
	mod := []byte("module " + c.Module + "\n\ngo 1.26\nrequire go.cratectl.invalid/dependency v1.0.0\n")
	return goPublicationFixtureMod(t, c, payload, mod), mod
}

func goPublicationFixtureMod(t testing.TB, c gomodule.Coordinate, payload string, mod []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, f := range []struct {
		name string
		data []byte
	}{{"go.mod", mod}, {"assets/owned.txt", []byte(payload)}} {
		w, e := z.Create(c.Module + "@" + c.Version + "/" + f.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(f.data); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func requirementDependencyFixture(t testing.TB) (gomodule.Coordinate, []byte, []byte) {
	t.Helper()
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/dependency", Version: "v1.0.0"}
	mod := []byte("module " + c.Module + "\n\ngo 1.26\n")
	return c, goPublicationFixtureMod(t, c, "owned inert requirement dependency bytes", mod), mod
}

func TestGoRequirementFixturesRetainActualTransitiveDependencyBytesAndPrunedSelection(t *testing.T) {
	root := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0"}
	archive, mod := goPublicationFixture(t, root, "owned export API bytes")
	dependency, depArchive, depMod := requirementDependencyFixture(t)
	corpus := map[gomodule.Coordinate]struct{ zip, mod []byte }{root: {archive, mod}, dependency: {depArchive, depMod}}
	graph, err := gomodule.ResolveRequirements(context.Background(), []byte("module owned/main\ngo 1.27.0\nrequire "+root.Module+" "+root.Version+"\n"), func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
		body, exists := corpus[c]
		if ctx.Err() != nil || !exists || int64(len(body.mod)) > maximum {
			return nil, gomodule.ErrGraphLimit
		}
		return body.mod, nil
	}, gomodule.DefaultGraphLimits())
	if err != nil || len(graph.Inputs) != 1 || len(graph.BuildList) != 2 || graph.BuildList[0].Source != root || graph.BuildList[1].Source != dependency {
		t.Fatal("fixture no longer requires the original transitive dependency", err)
	}
	for _, selected := range graph.BuildList {
		body, exists := corpus[selected.Source]
		if !exists {
			t.Fatal("selected dependency omitted from physical fixture")
		}
		info, err := gomodule.VersionInfo(selected.Source, "2026-01-02T03:04:05Z")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gomodule.InspectRepresentations(context.Background(), bytes.NewReader(body.zip), int64(len(body.zip)), selected.Source, body.mod, info, ziparchive.Limits{CompressedBytes: 1 << 20, ExpandedBytes: 1 << 20, DirectoryBytes: 128 << 10, Files: 8}); err != nil {
			t.Fatal("owned selected original representations do not agree", err)
		}
	}
}
