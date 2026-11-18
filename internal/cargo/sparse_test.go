// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"errors"
	"strings"
	"testing"
)

const sparseChecksum = "f6e3c6697574514abbf8cb54bb6886840c89f1bb9e85b69d64b7fd58690e06aa"
const sparseLine = `{"name":"Owned_Crate","vers":"1.2.3+ci","deps":[{"name":"alias","req":"^1.0","features":["b","a"],"optional":true,"default_features":false,"target":null,"kind":null,"registry":null,"package":"leaf"}],"cksum":"` + sparseChecksum + `","features":{"base":["a","b"]},"features2":{"base":["dep:alias"],"Extra":[]},"yanked":false,"v":2,"rust_version":"1.90","pubtime":"2026-11-18T12:00:00Z"}`

func TestSparseIndexBindsOneCrateAndUniqueVersions(t *testing.T) {
	entries, err := ParseSparseIndex([]byte(sparseLine+"\r\n"), "owned_crate", 2)
	if err != nil || len(entries) != 1 {
		t.Fatalf("parse valid sparse index = %v, %v", entries, err)
	}
	entry := entries[0]
	if entry.Checksum != sparseChecksum || entry.Yanked || entry.Format != 2 || len(entry.Dependencies) != 1 {
		t.Fatalf("unexpected sparse fields: %+v", entry)
	}
	dep := entry.Dependencies[0]
	if dep.Package != "leaf" || dep.Kind != "normal" || !dep.Optional || dep.DefaultFeatures {
		t.Fatalf("unexpected dependency binding: %+v", dep)
	}
	for _, tc := range []struct {
		name, content string
		limit         int
		want          error
	}{
		{"case alias", strings.Replace(sparseLine, `"vers":`, `"VERS":`, 1), 2, ErrInput},
		{"duplicate checksum", strings.Replace(sparseLine, `"cksum":`, `"cksum":"x","cksum":`, 1), 2, ErrInput},
		{"duplicate dependency field", strings.Replace(sparseLine, `"registry":null`, `"registry":null,"registry":null`, 1), 2, ErrInput},
		{"different crate", strings.Replace(sparseLine, `"Owned_Crate"`, `"different"`, 1), 2, ErrInput},
		{"missing required flag", strings.Replace(sparseLine, `,"optional":true`, "", 1), 2, ErrInput},
		{"null yanked", strings.Replace(sparseLine, `"yanked":false`, `"yanked":null`, 1), 2, ErrInput},
		{"separate registry", strings.Replace(sparseLine, `"registry":null`, `"registry":"sparse+https://registry.example/"`, 1), 2, ErrInput},
		{"unsupported schema", strings.Replace(sparseLine, `"v":2`, `"v":3`, 1), 2, ErrInput},
		{"mixed package spelling", sparseLine + "\n" + strings.NewReplacer(`"Owned_Crate"`, `"owned_crate"`, "1.2.3+ci", "1.3.0").Replace(sparseLine), 2, ErrInput},
		{"same version build alias", sparseLine + "\n" + strings.Replace(sparseLine, "1.2.3+ci", "1.2.3+other", 1), 2, ErrInput},
		{"version budget", sparseLine + "\n" + strings.Replace(sparseLine, "1.2.3+ci", "1.3.0", 1), 1, ErrLimit},
		{"row budget", strings.Repeat(" ", MaxIndexBytes) + sparseLine, 2, ErrLimit},
		{"blank row", sparseLine + "\n\n", 2, ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSparseIndex([]byte(tc.content), "owned_crate", tc.limit)
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("parse = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}

func TestSparseArchiveChecksResolutionGraph(t *testing.T) {
	entries, err := ParseSparseIndex([]byte(sparseLine), "owned_crate", 1)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[0]
	archive := Entry{Name: entry.Name, Version: entry.Version, RustVersion: "1.90",
		Features:     map[string][]string{"base": {"dep:alias", "b", "a"}, "Extra": {}},
		Dependencies: []Dependency{{Name: "alias", Package: "leaf", Kind: "normal", Requirement: "1.0", Optional: true, Features: []string{"a", "b"}}}}
	if !entry.MatchesArchive(archive) {
		t.Fatal("matching normalized Cargo resolution graph was refused")
	}
	archive.Dependencies[0].DefaultFeatures = true
	if entry.MatchesArchive(archive) {
		t.Fatal("different feature activation was accepted")
	}
}

func TestSparseDownloadTemplate(t *testing.T) {
	const template = "https://downloads.example/dist/{prefix}/{lowerprefix}/{crate}/{version}/{sha256-checksum}.crate"
	config, err := ParseDownloadTemplate([]byte(`{"dl":"` + template + `","auth-required":true}`))
	if err != nil || config != template {
		t.Fatalf("parse template = %q, %v", config, err)
	}
	entry := SparseEntry{Entry: Entry{Name: "Owned_Crate", Version: "1.2.3+ci", Checksum: sparseChecksum}}
	for _, tc := range []struct{ template, want string }{
		{template, "https://downloads.example/dist/Ow/ne/ow/ne/Owned_Crate/1.2.3+ci/" + sparseChecksum + ".crate"},
		{"https://downloads.example/api/", "https://downloads.example/api/Owned_Crate/1.2.3+ci/download"},
		{"https://downloads.example/{other}", ""},
		{"https://downloads.example/{crate}?token=fixture", ""},
		{"https://operator@downloads.example/{crate}", ""},
		{"https://{crate}.example/dist/{crate}", ""},
		{"file:///tmp/{crate}", ""},
	} {
		got, err := DownloadURL(tc.template, entry)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("download URL for %q = %q, %v, want %q", tc.template, got, err, tc.want)
		}
	}
}
