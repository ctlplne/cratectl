// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestCargoSparsePathsAndVersionUniqueness(t *testing.T) {
	for name, want := range map[string]string{"A": "1/a", "Ab": "2/ab", "AbC": "3/a/abc", "Ab_CD": "ab/_c/ab_cd"} {
		got, err := IndexPath(name)
		if err != nil || got != want {
			t.Fatalf("index path for %q: %q, %v", name, got, err)
		}
	}
	first, err := ArtifactPath("Ab_CD", "1.2.3-pre.1+build")
	second, otherErr := ArtifactPath("ab-cd", "1.2.3-pre.1")
	if err != nil || otherErr != nil || first != second || first != "crates/ab-cd/1.2.3-pre.1.crate" {
		t.Fatalf("normalized coordinates differ: %q, %q, %v, %v", first, second, err, otherErr)
	}
	for _, version := range []string{"1", "1.2", "v1.2.3", "1.2.03", "1.2.3-01", "18446744073709551616.2.3"} {
		if _, err = VersionKey(version); !errors.Is(err, ErrInput) {
			t.Fatalf("invalid version %q: %v", version, err)
		}
	}
}

func TestCargoPublishFrameReadsOnlyBoundedMetadataAndArchiveLength(t *testing.T) {
	frame := func(metadata string, size uint32) *bytes.Reader {
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, uint32(len(metadata)))
		data.WriteString(metadata)
		binary.Write(&data, binary.LittleEndian, size)
		data.WriteString("inert archive")
		return bytes.NewReader(data.Bytes())
	}
	raw := frame(`{"name":"foo","vers":"1.2.3","readme":"owned fixture"}`, 13)
	c, size, err := ReadPublish(raw)
	if err != nil || c != (Coordinate{"foo", "1.2.3"}) || size != 13 || raw.Len() != 13 {
		t.Fatalf("bad frame: %v %d trailing=%d %v", c, size, raw.Len(), err)
	}
	for _, bad := range []string{`null`, `{"Name":"foo","vers":"1.2.3"}`, `{"name":"foo","name":"bar","vers":"1.2.3"}`, `{"name":"foo","vers":"1.2.3"} {}`} {
		if _, _, err = ReadPublish(frame(bad, 13)); !errors.Is(err, ErrInput) {
			t.Fatalf("invalid frame accepted: %s, %v", bad, err)
		}
	}
	if _, _, err = ReadPublish(frame(`{"name":"foo","vers":"1.2.3"}`, MaxUploadBytes+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized declared archive: %v", err)
	}
}

func TestCargoArchiveProjectsTheNormalizedManifest(t *testing.T) {
	const manifest = `
[package]
name = "cratectl-demo"
version = "1.2.3"
rust-version = "1.89"

[features]
more = ["dep:renamed", "renamed?/extras"]

[dependencies.renamed]
package = "cratectl-library"
registry-index = "sparse+https://127.0.0.1:38443/cargo/packages/index/"
version = "1.3, <2"
optional = true
default-features = false
features = ["extras"]

[target.'cfg(windows)'.build-dependencies]
cratectl-build = "^0.4"
`
	pkg := Coordinate{"cratectl-demo", "1.2.3"}
	archive := func(t *testing.T, source string) []byte {
		t.Helper()
		var data bytes.Buffer
		z := gzip.NewWriter(&data)
		tw := tar.NewWriter(z)
		for _, file := range []struct{ name, body string }{
			{"cratectl-demo-1.2.3/Cargo.toml", source},
			{"cratectl-demo-1.2.3/src/lib.rs", "// inert fixture\n"},
		} {
			if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0600, Size: int64(len(file.body))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(file.body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return data.Bytes()
	}
	index := "sparse+https://127.0.0.1:38443/cargo/packages/index/"
	data := archive(t, manifest)
	entry, err := ReadArchive(t.Context(), bytes.NewReader(data), pkg, index)
	if err != nil || entry.Name != pkg.Name || entry.Version != pkg.Version || entry.RustVersion != "1.89" ||
		len(entry.Dependencies) != 2 || len(entry.Features["more"]) != 2 {
		t.Fatalf("manifest projection: %+v, %v", entry, err)
	}
	alias, target := entry.Dependencies[0], entry.Dependencies[1]
	if alias.Name != "renamed" || alias.Package != "cratectl-library" || alias.DefaultFeatures || !alias.Optional ||
		len(alias.Features) != 1 || target.Kind != "build" || target.Target != "cfg(windows)" || !target.DefaultFeatures {
		t.Fatalf("dependency projection: %+v", entry.Dependencies)
	}
	for _, c := range []Coordinate{{"cratectl-demo", "1.2.4"}, {"different-demo", "1.2.3"}} {
		if _, err = ReadArchive(context.Background(), bytes.NewReader(data), c, index); !errors.Is(err, ErrInput) {
			t.Fatalf("archive with different identity accepted: %+v, %v", c, err)
		}
	}
	if _, err = ReadArchive(t.Context(), bytes.NewReader(data), pkg, "sparse+https://example.invalid/index/"); !errors.Is(err, ErrInput) {
		t.Fatalf("archive pointing to a different dependency authority accepted: %v", err)
	}
	if _, err = ReadArchive(t.Context(), bytes.NewReader(append(data, ' ')), pkg, index); !errors.Is(err, ErrInput) {
		t.Fatalf("trailing archive data accepted: %v", err)
	}
}
