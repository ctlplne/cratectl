// SPDX-License-Identifier: BUSL-1.1
package cran

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProxyCatalogRequiresStrongChecksumsAndExactSourceCoordinates(t *testing.T) {
	ctx := context.Background()
	sha := strings.Repeat("a", 64)
	md5 := strings.Repeat("b", 32)
	record := "Package: CratectlStats\nVersion: 1.2-3\nImports: Cratectl.Data (>= 2.2-0),\n R (>= 4.3)\nMD5sum: " + md5 + "\nSHA256sum: " + sha
	other := strings.ReplaceAll(record, "CratectlStats", "CratectlExtra")
	input := []byte(strings.ReplaceAll(record+"\n\n"+other, "\n", "\r\n"))
	entries, err := ParseProxyCatalog(ctx, input, 2, MaxCatalogBytes)
	if err != nil || len(entries) != 2 {
		t.Fatalf("valid folded records: %v (%d)", err, len(entries))
	}
	entry := entries[0]
	plain := entry.Coordinate()
	path := PinnedSourcePath(plain, entry.SHA256)
	coordinate, digest, valid := ParsePinnedSourcePath(path)
	if !valid || coordinate != plain || digest != sha || entry.Description["Imports"] != "Cratectl.Data (>= 2.2-0), R (>= 4.3)" ||
		entry.Matches(entry.Description, strings.Repeat("c", 32)) {
		t.Fatal("catalog lost the exact coordinate, requirement or checksum binding")
	}
	for _, invalid := range []string{
		strings.Replace(record, "SHA256sum: "+sha, "", 1),
		strings.Replace(record, "MD5sum: "+md5, "", 1),
		record + "\nsha256sum: " + sha,
		record + "\n\n" + record,
		record + "\nPath: alternate",
		record + "\nBuilt: R 4.6.2",
		strings.Replace(record, "Version: 1.2-3", "Version: next", 1),
	} {
		if _, err := ParseProxyCatalog(ctx, []byte(invalid), 3, MaxCatalogBytes); !errors.Is(err, ErrCatalog) {
			t.Errorf("admitted invalid catalog %q: %v", invalid, err)
		}
	}
	if _, err := ParseProxyCatalog(ctx, input, 1, MaxCatalogBytes); !errors.Is(err, ErrCatalog) {
		t.Fatal("expected complete row budget", err)
	}
	if _, err := ParseProxyCatalog(ctx, input, 2, int64(len(input)-1)); !errors.Is(err, ErrCatalog) {
		t.Fatal("expected byte budget", err)
	}
}
