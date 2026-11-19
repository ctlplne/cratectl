// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"strings"
	"testing"
)

func TestDistributionResolvesOnlySelectedArchitecturePaths(t *testing.T) {
	d := &Distribution{Suite: "stable", Component: "main", Architectures: []string{"amd64", "arm64"}}
	if !d.Valid() || !d.SupportsArchitecture("all") || d.SupportsArchitecture("i386") || d.ReleasePath() != "dists/stable/InRelease" {
		t.Fatal("invalid selected Debian distribution")
	}
	prefix := "dists/stable/main/binary-arm64/"
	sha := strings.Repeat("a", 64)
	for path, expected := range map[string]IndexRequest{
		prefix + "Packages":              {Architecture: "arm64", Name: "Packages"},
		prefix + "by-hash/SHA256/" + sha: {Architecture: "arm64", SHA256: sha},
	} {
		if actual, ok := d.ResolveIndex(path); !ok || actual != expected {
			t.Fatal("Debian index path did not retain its exact selection", actual, ok)
		}
	}
	for _, path := range []string{"Packages", prefix + "Packages.xz", "dists/stable/main/binary-i386/Packages", "dists/testing/main/binary-arm64/Packages", prefix + "by-hash/SHA256/short"} {
		if _, ok := d.ResolveIndex(path); ok {
			t.Fatal("accepted an unselected Debian path", path)
		}
	}
	flat, ok := (*Distribution)(nil).ResolveIndex("Packages.gz")
	if !ok || flat != (IndexRequest{Name: "Packages.gz"}) {
		t.Fatal("legacy flat distribution did not resolve its canonical index")
	}
	d.Architectures = []string{"arm64", "arm64"}
	if d.Valid() {
		t.Fatal("accepted duplicate architectures")
	}
}
