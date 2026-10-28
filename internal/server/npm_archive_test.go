// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"
)

type npmArchiveEntry struct {
	name, body, link string
	kind             byte
}

func npmArchiveFixture(t testing.TB, entries []npmArchiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	archive := tar.NewWriter(gz)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		if e := archive.WriteHeader(&tar.Header{Name: entry.name, Size: int64(len(entry.body)), Mode: 0644, Typeflag: kind, Linkname: entry.link}); e != nil {
			t.Fatal(e)
		}
		if _, e := archive.Write([]byte(entry.body)); e != nil {
			t.Fatal(e)
		}
	}
	if e := archive.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

func TestNPMArchiveManifestAndBounds(t *testing.T) {
	manifest := npmArchiveEntry{name: "package/package.json", body: `{"name":"@scope/pkg","version":"1.2.3-beta.1+build.7","dependencies":{"dep":"1.0.0"}}`}
	regular := npmArchiveEntry{name: "package/index.js", body: "module.exports = 42;"}
	valid := npmArchiveFixture(t, []npmArchiveEntry{manifest, regular, {name: "package/link.js", kind: tar.TypeSymlink, link: "index.js"}})
	pkg, e := npmArchivePackage(valid, "@scope/pkg", "1.2.3-beta.1", 64<<10, 10, 1024)
	if e != nil || pkg["version"] != "1.2.3-beta.1" || pkg["dependencies"].(map[string]any)["dep"] != "1.0.0" {
		t.Fatalf("native normalized coordinate or archive metadata was lost: %v %v", pkg, e)
	}
	tests := []struct {
		name    string
		entries []npmArchiveEntry
	}{
		{"missing manifest", []npmArchiveEntry{regular}},
		{"duplicate manifest", []npmArchiveEntry{manifest, manifest}},
		{"parent traversal", []npmArchiveEntry{manifest, {name: "package/../../escape"}}},
		{"absolute path", []npmArchiveEntry{manifest, {name: "/package/escape"}}},
		{"windows path", []npmArchiveEntry{manifest, {name: `package\escape`}}},
		{"windows stream path", []npmArchiveEntry{manifest, {name: "package/file:stream"}}},
		{"file as parent", []npmArchiveEntry{manifest, {name: "package/dir"}, {name: "package/dir/file"}}},
		{"escaping link", []npmArchiveEntry{manifest, {name: "package/link", kind: tar.TypeSymlink, link: "../escape"}}},
		{"link parent redirection", []npmArchiveEntry{manifest, {name: "package/dir/link", kind: tar.TypeSymlink, link: ".."}, {name: "package/dir", kind: tar.TypeSymlink, link: "."}}},
		{"link cycle", []npmArchiveEntry{manifest, {name: "package/a", kind: tar.TypeSymlink, link: "b"}, {name: "package/b", kind: tar.TypeSymlink, link: "a"}}},
		{"device", []npmArchiveEntry{manifest, {name: "package/device", kind: tar.TypeChar}}},
		{"wrong package", []npmArchiveEntry{{name: "package/package.json", body: `{"name":"other","version":"1.2.3-beta.1"}`}}},
		{"wrong version", []npmArchiveEntry{{name: "package/package.json", body: `{"name":"@scope/pkg","version":"1.2.4"}`}}},
		{"trailing manifest JSON", []npmArchiveEntry{{name: "package/package.json", body: manifest.body + ` {}`}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := npmArchivePackage(npmArchiveFixture(t, tc.entries), "@scope/pkg", "1.2.3-beta.1", 64<<10, 10, 1024); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	for _, budget := range []struct {
		expanded int64
		files    int
		json     int64
	}{{1024, 10, 1024}, {64 << 10, 1, 1024}, {64 << 10, 10, 8}} {
		if _, e := npmArchivePackage(valid, "@scope/pkg", "1.2.3-beta.1", budget.expanded, budget.files, budget.json); e == nil {
			t.Fatal("archive exceeded safety budget")
		}
	}
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 1
	for _, data := range [][]byte{corrupt, valid[:len(valid)-8], append(bytes.Clone(valid), valid...), append(bytes.Clone(valid), []byte("tail")...)} {
		if _, e := npmArchivePackage(data, "@scope/pkg", "1.2.3-beta.1", 64<<10, 10, 1024); e == nil {
			t.Fatal("corrupt or trailing gzip data accepted")
		}
	}
}

func FuzzNPMArchive(f *testing.F) {
	f.Add(npmArchiveFixture(f, []npmArchiveEntry{{name: "package/package.json", body: `{"name":"pkg","version":"1.0.0"}`}}))
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		pkg, e := npmArchivePackage(data, "pkg", "1.0.0", 64<<10, 32, 1024)
		if e == nil {
			encoded, e := json.Marshal(pkg)
			if e != nil || len(encoded) == 0 || pkg["name"] != "pkg" || pkg["version"] != "1.0.0" {
				t.Fatal("accepted manifest lost coordinate")
			}
		}
	})
}
