// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
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

// Add inert, poorly compressible padding without changing the original project
// or asset members. This gives the native range interruption a real second range.
func goPublicationFixturePaddedMod(t testing.TB, c gomodule.Coordinate, payload string, mod []byte) []byte {
	t.Helper()
	original := goPublicationFixtureMod(t, c, payload, mod)
	input, err := zip.NewReader(bytes.NewReader(original), int64(len(original)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for _, member := range input.File {
		if err := z.Copy(member); err != nil {
			t.Fatal(err)
		}
	}
	w, err := z.Create(c.Module + "@" + c.Version + "/assets/padding.txt")
	if err != nil {
		t.Fatal(err)
	}
	for n := range 5000 {
		if _, err := io.WriteString(w, crypt.Digest([]byte(fmt.Sprintf("cratectl-owned-range-padding-%d", n)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestGoRequirementNativePaddingPreservesOriginalMembersAndRequiresSecondRange(t *testing.T) {
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/competing", Version: "v1.1.0"}
	mod, asset := []byte("module "+c.Module+"\ngo 1.26\n"), "owned inert requirement asset"
	raw := goPublicationFixturePaddedMod(t, c, asset, mod)
	if len(raw) <= 2*65536 || len(raw) > 1<<20 {
		t.Fatal("native fixture no longer requires the second64KiB range within the existing1MiB budget", len(raw))
	}
	r, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(r.File) != 3 {
		t.Fatal("padded fixture changed original member inventory", err)
	}
	for n, expected := range [][]byte{mod, []byte(asset)} {
		file, err := r.File[n].Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.LimitReader(file, 1<<20))
		file.Close()
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatal("padding changed an original metadata/asset member", n, err)
		}
	}
	info, err := gomodule.VersionInfo(c, "2026-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gomodule.InspectRepresentations(context.Background(), bytes.NewReader(raw), int64(len(raw)), c, mod, info, ziparchive.Limits{CompressedBytes: 1 << 20, ExpandedBytes: 1 << 20, DirectoryBytes: 128 << 10, Files: 8}); err != nil {
		t.Fatal("padding broke original native representations", err)
	}
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
