// SPDX-License-Identifier: BUSL-1.1
package cran

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

const validDescription = "Package: CratectlStat\r\nVersion: 1.2-3\r\nTitle: Owned CRAN Fixture\r\n" +
	"Description: First line\r\n    then a continuation.\r\nLicense: MIT\r\nDepends: R (>= 4.0)\r\n" +
	"Imports: Cratectl.Data (>= 2.1-0),\r\n    metrics\r\nNeedsCompilation: no\r\nMD5sum: supplied-and-ignored\r\n"

func TestDescriptionFoldsFieldsAndKeepsNativeDependencies(t *testing.T) {
	const filename = "src/contrib/CratectlStat_1.2-3.tar.gz"
	c, ok := ParsePath(filename)
	if !ok || c.Path() != filename {
		t.Fatalf("unexpected coordinate: %+v", c)
	}
	data := sourceArchive(t, [2]string{"CratectlStat/DESCRIPTION", validDescription}, [2]string{"CratectlStat/inst/owned.txt", "inert fixture"})
	p, err := Inspect(context.Background(), bytes.NewReader(data), int64(len(data)), c)
	if err != nil {
		t.Fatal(err)
	}
	want := "Package: CratectlStat\nVersion: 1.2-3\nDepends: R (>= 4.0)\nImports: Cratectl.Data (>= 2.1-0), metrics\n" +
		"License: MIT\nNeedsCompilation: no\nTitle: Owned CRAN Fixture\nDescription: First line then a continuation.\nMD5sum: " + strings.Repeat("a", 32) + "\n\n"
	if got := p.IndexEntry(strings.Repeat("a", 32), ""); got != want {
		t.Fatalf("unexpected DCF index:\n%s", got)
	}
}

func TestDescriptionRejectsAmbiguousNamesAndExtraRecords(t *testing.T) {
	c := Coordinate{Name: "CratectlStat", Version: "1.2-3"}
	for _, input := range []string{
		validDescription + "package: CratectlDuplicate\n",
		validDescription + "\nPackage: CratectlDuplicate\n",
		strings.Replace(validDescription, "Cratectl.Data (>= 2.1-0)", "https://example.invalid/Cratectl.Data", 1),
		strings.Replace(validDescription, "Version: 1.2-3", "Version: 2.0", 1),
		strings.Replace(validDescription, "Title: Owned CRAN Fixture", "Title: Not\x00DCF", 1),
	} {
		if _, err := parseDescription([]byte(input), c); !errors.Is(err, ErrPackage) {
			t.Errorf("accepted invalid DESCRIPTION: %v", err)
		}
	}
}

func TestArchiveRejectsDuplicatePathsAndIncompleteCompression(t *testing.T) {
	c := Coordinate{Name: "CratectlStat", Version: "1.2-3"}
	metadata := [2]string{"CratectlStat/DESCRIPTION", validDescription}
	valid := sourceArchive(t, metadata)
	for _, scenario := range []struct {
		label string
		bytes []byte
	}{
		{"duplicate description", sourceArchive(t, metadata, metadata)},
		{"ambiguous directory", sourceArchive(t, metadata, [2]string{"CratectlStat/../Other.txt", "owned fixture"})},
		{"truncated CRC", valid[:len(valid)-3]},
		{"extra gzip member", bytes.Join([][]byte{valid, valid}, nil)},
	} {
		t.Run(scenario.label, func(t *testing.T) {
			if _, err := Inspect(context.Background(), bytes.NewReader(scenario.bytes), int64(len(scenario.bytes)), c); !errors.Is(err, ErrPackage) {
				t.Errorf("accepted invalid source archive: %v", err)
			}
		})
	}
}

func sourceArchive(t *testing.T, files ...[2]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compression := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compression)
	for _, file := range files {
		if err := archive.WriteHeader(&tar.Header{Name: file[0], Size: int64(len(file[1])), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, file[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compression.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
