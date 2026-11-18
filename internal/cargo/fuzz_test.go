// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func FuzzCargoSparseIndex(f *testing.F) {
	f.Add([]byte(sparseLine + "\n"))
	f.Add([]byte(strings.Replace(sparseLine, "1.2.3+ci", "2.0.0-rc.1", 1)))
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			return
		}
		entries, err := ParseSparseIndex(input, "owned_crate", 12)
		if err != nil {
			return
		}
		if len(entries) == 0 || len(entries) > 12 {
			t.Fatalf("accepted unexpected entry count %d", len(entries))
		}
		var projected bytes.Buffer
		for _, row := range entries {
			if err := json.NewEncoder(&projected).Encode(row); err != nil {
				t.Fatal(err)
			}
		}
		again, err := ParseSparseIndex(projected.Bytes(), "owned_crate", 12)
		if err != nil || !reflect.DeepEqual(entries, again) {
			t.Fatalf("accepted metadata cannot round-trip: %v", err)
		}
	})
}

func FuzzCargoPublishFrame(f *testing.F) {
	metadata := []byte(`{"name":"cratectl-cargo-fuzz","vers":"1.0.0"}`)
	frame := binary.LittleEndian.AppendUint32(nil, uint32(len(metadata)))
	frame = append(frame, metadata...)
	frame = binary.LittleEndian.AppendUint32(frame, 4)
	frame = append(frame, []byte("test")...)
	f.Add(frame)
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxMetadataBytes+64 {
			return
		}
		reader := bytes.NewReader(input)
		coordinate, size, err := ReadPublish(reader)
		if err != nil {
			return
		}
		header := int(binary.LittleEndian.Uint32(input)) + 8
		if header < 9 || header+reader.Len() != len(input) || size <= 0 || size > MaxUploadBytes {
			t.Fatalf("accepted frame outside its bounds: %d, %d", header, size)
		}
		if _, err := ArtifactPath(coordinate.Name, coordinate.Version); err != nil {
			t.Fatal("accepted invalid publish coordinates")
		}
	})
}

func FuzzCargoNormalizedArchive(f *testing.F) {
	const manifest = "[package]\nname = \"cratectl-cargo-fuzz\"\nversion = \"1.0.0\"\n"
	var packed bytes.Buffer
	z := gzip.NewWriter(&packed)
	tw := tar.NewWriter(z)
	if err := tw.WriteHeader(&tar.Header{Name: "cratectl-cargo-fuzz-1.0.0/Cargo.toml", Mode: 0600, Size: int64(len(manifest))}); err != nil {
		f.Fatal(err)
	}
	if _, err := tw.Write([]byte(manifest)); err != nil {
		f.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		f.Fatal(err)
	}
	if err := z.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(packed.Bytes())
	f.Add([]byte("not a Cargo file"))
	const index = "sparse+https://packages.example/index/"
	coordinate := Coordinate{Name: "cratectl-cargo-fuzz", Version: "1.0.0"}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			return
		}
		entry, err := ReadArchive(t.Context(), bytes.NewReader(input), coordinate, index)
		if err != nil {
			return
		}
		if entry.Name != coordinate.Name || entry.Version != coordinate.Version || entry.Features == nil || entry.Dependencies == nil {
			t.Fatal("accepted an archive with a different identity or missing resolution data")
		}
	})
}

func FuzzCargoDownloadTemplate(f *testing.F) {
	f.Add([]byte(`{"dl":"https://packages.example/{lowerprefix}/{crate}/{version}.crate"}`))
	f.Add([]byte(`{"dl":"https://packages.example/crates"}`))
	f.Add([]byte(`{"dl":"https://packages.example/{crate}/{sha256-checksum}"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16<<10 {
			return
		}
		template, err := ParseDownloadTemplate(input)
		if err != nil {
			return
		}
		entry := SparseEntry{Entry: Entry{Name: "Own_Crate", Version: "1.0.0+build", Checksum: sparseChecksum}}
		address, err := DownloadURL(template, entry)
		if err != nil {
			return
		}
		base, baseErr := url.Parse(template)
		final, finalErr := url.Parse(address)
		if baseErr != nil || finalErr != nil || final.Host != base.Host || final.Scheme != base.Scheme ||
			final.User != nil || final.RawQuery != "" || final.ForceQuery || final.Fragment != "" || strings.ContainsAny(address, "{}%\r\n\x00") {
			t.Fatal("template expansion changed an authority or introduced unsupported URL syntax")
		}
	})
}
