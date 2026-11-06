// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"testing"

	cryptox "ctlplne.dev/cratectl/internal/crypto"
	"golang.org/x/mod/sumdb/dirhash"
)

func TestInspectedArchiveHashesMatchStandardGoOnOriginalZIPAndMod(t *testing.T) {
	for _, c := range []Coordinate{testCoordinate, {"go.cratectl.invalid/Owned/app/v2", "v2.0.0"}, {testCoordinate.Module, "v1.0.1-0.20260102030405-0123456789ab"}} {
		files := append(baseFiles(c), fixtureFile{name: "", mode: fs.ModeDir | 0700}, fixtureFile{name: "assets/", mode: fs.ModeDir | 0700}, fixtureFile{name: "assets/Σ.txt", body: "opaque\x00\xff"})
		var first string
		for _, reverse := range []bool{false, true} {
			if reverse {
				for a, b := 0, len(files)-1; a < b; a, b = a+1, b-1 {
					files[a], files[b] = files[b], files[a]
				}
			}
			data := moduleFixture(t, c, files)
			archive, err := InspectArchive(context.Background(), bytes.NewReader(data), int64(len(data)), c, testLimits)
			if err != nil {
				t.Fatal(err)
			}
			path := t.TempDir() + "/cratectl-owned.zip"
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			want, err := dirhash.HashZip(path, dirhash.Hash1)
			if err != nil || archive.ZIPHash != want {
				t.Fatal("inspected ZIP differs from stock Go checksum", err)
			}
			modHash, err := cryptox.GoModHash(archive.GoMod)
			if err != nil || archive.GoModHash != modHash {
				t.Fatal("inspected go.mod differs from original bytes", err)
			}
			if reverse && archive.ZIPHash != first {
				t.Fatal("ZIP ordering changed logical contents checksum")
			}
			first = archive.ZIPHash
		}
	}
}
