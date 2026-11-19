// SPDX-License-Identifier: BUSL-1.1
package conda

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

func TestInspectMatchesCoordinateAndKeepsDependencySpecs(t *testing.T) {
	data, err := os.ReadFile("testdata/cratectl-conda-valid.tar.bz2")
	if err != nil {
		t.Fatal(err)
	}
	const path = "noarch/cratectl-conda-archive-1.2.0-hfixture_1.tar.bz2"
	coordinate, ok := ParsePath(path)
	if !ok || coordinate.Path() != path {
		t.Fatalf("coordinate did not round trip: %+v", coordinate)
	}
	metadata, err := Inspect(context.Background(), bytes.NewReader(data), int64(len(data)), coordinate)
	if err != nil || metadata.BuildNumber == nil || *metadata.BuildNumber != 1 ||
		!slices.Equal(metadata.Depends, []string{"cratectl-conda-dependency >=1.0"}) ||
		!slices.Equal(metadata.Constrains, []string{"cratectl-conda-extra >=2.0"}) {
		t.Fatalf("archive index did not preserve its metadata: %+v, %v", metadata, err)
	}
}

func TestInspectRejectsDuplicateIndexMismatchAndTruncation(t *testing.T) {
	valid, err := os.ReadFile("testdata/cratectl-conda-valid.tar.bz2")
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := os.ReadFile("testdata/cratectl-conda-duplicate.tar.bz2")
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		name   string
		path   string
		binary []byte
	}{
		{"duplicate index", "noarch/cratectl-conda-archive-1.2.0-hfixture_1.tar.bz2", duplicate},
		{"different subdir", "linux-64/cratectl-conda-archive-1.2.0-hfixture_1.tar.bz2", valid},
		{"truncated checksum", "noarch/cratectl-conda-archive-1.2.0-hfixture_1.tar.bz2", valid[:len(valid)-6]},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			coordinate, ok := ParsePath(candidate.path)
			if !ok {
				t.Fatal("invalid fixture coordinate")
			}
			if _, err := Inspect(context.Background(), bytes.NewReader(candidate.binary), int64(len(candidate.binary)), coordinate); !errors.Is(err, ErrPackage) {
				t.Fatalf("invalid archive: %v", err)
			}
		})
	}
}

func TestDependencySpecsStayWithinConfiguredChannels(t *testing.T) {
	for _, spec := range []string{"__glibc >=2.17,<3.0.a0", "cratectl-dep 1.2.* h_0", "cratectl-dep"} {
		if !validDependency(spec) {
			t.Errorf("unexpectedly rejected %q", spec)
		}
	}
	for _, spec := range []string{"other::cratectl-dep", "cratectl-dep[url=https://example.invalid/pkg]", "cratectl-dep\n1.0", "cratectl-dep 1.0 ../h_0"} {
		if validDependency(spec) {
			t.Errorf("unexpectedly accepted %q", spec)
		}
	}
}
