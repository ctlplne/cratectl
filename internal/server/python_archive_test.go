// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
)

func pythonWheelFixture(t testing.TB, core string, extra map[string]string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	entries := map[string]string{"pkg-1.0.dist-info/METADATA": core, "pkg/__init__.py": "value = 42\n"}
	for k, v := range extra {
		entries[k] = v
	}
	for name, data := range entries {
		file, e := writer.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.Write([]byte(data)); e != nil {
			t.Fatal(e)
		}
	}
	if e := writer.Close(); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}
func TestPythonSourceArchiveWithoutExecution(t *testing.T) {
	core := "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\nRequires-Dist: dep==1.0\n\n"
	build := func(link string) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		for name, value := range map[string]string{"pkg-1.0/PKG-INFO": core, "pkg-1.0/setup.py": "raise RuntimeError('must never execute')"} {
			if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(value))}); e != nil {
				t.Fatal(e)
			}
			if _, e := tw.Write([]byte(value)); e != nil {
				t.Fatal(e)
			}
		}
		if link != "" {
			if e := tw.WriteHeader(&tar.Header{Name: "pkg-1.0/link", Typeflag: tar.TypeSymlink, Linkname: link, Mode: 0644}); e != nil {
				t.Fatal(e)
			}
		}
		tw.Close()
		gz.Close()
		return out.Bytes()
	}
	data := build("")
	result, e := inspectPythonDistribution(context.Background(), bytes.NewReader(data), int64(len(data)), "pkg-1.0.tar.gz", pythonArchiveBudget{64 << 10, 20, 4096})
	if e != nil || result.Raw != core {
		t.Fatal("source metadata read required execution or changed bytes", e)
	}
	data = build("../../escape")
	if _, e := inspectPythonDistribution(context.Background(), bytes.NewReader(data), int64(len(data)), "pkg-1.0.tar.gz", pythonArchiveBudget{64 << 10, 20, 4096}); e == nil {
		t.Fatal("escaping source link accepted")
	}
}
func TestPythonArchiveIdentityAndBudgets(t *testing.T) {
	core := "Metadata-Version: 2.4\nName: Pkg\nVersion: 1.0\nRequires-Python: >=3.10\nRequires-Dist: dep==1.0\n\nDescription\n"
	budget := pythonArchiveBudget{64 << 10, 20, 4096}
	data := pythonWheelFixture(t, core, nil)
	result, e := inspectPythonDistribution(context.Background(), bytes.NewReader(data), int64(len(data)), "pkg-1.0-py3-none-any.whl", budget)
	if e != nil || result.Name != "pkg" || result.RequiresPython != ">=3.10" || result.Raw != core {
		t.Fatal("embedded identity or exact metadata bytes lost", result, e)
	}
	for _, tc := range []struct {
		name, body string
		extra      map[string]string
	}{
		{"wrong name", "Metadata-Version: 2.4\nName: other\nVersion: 1.0\n\n", nil},
		{"wrong version", "Metadata-Version: 2.4\nName: pkg\nVersion: 2.0\n\n", nil},
		{"duplicate identity", "Metadata-Version: 2.4\nName: pkg\nName: other\nVersion: 1.0\n\n", nil},
		{"traversal", core, map[string]string{"../escape": "fixture"}},
		{"windows path", core, map[string]string{`pkg\escape`: "fixture"}},
		{"case collision", core, map[string]string{"PKG/__init__.py": "fixture"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pythonWheelFixture(t, tc.body, tc.extra)
			if _, e := inspectPythonDistribution(context.Background(), bytes.NewReader(data), int64(len(data)), "pkg-1.0-py3-none-any.whl", budget); e == nil {
				t.Fatal("unsafe Python distribution accepted")
			}
		})
	}
	for _, b := range []pythonArchiveBudget{{8, 20, 8}, {64 << 10, 1, 4096}, {64 << 10, 20, 8}} {
		if _, e := inspectPythonDistribution(context.Background(), bytes.NewReader(data), int64(len(data)), "pkg-1.0-py3-none-any.whl", b); e == nil {
			t.Fatal("archive safety budget ignored")
		}
	}
	for _, filename := range []string{"pkg-1.0-../py3-none-any.whl", "pkg-1.0-badbuild-py3-none-any.whl", "pkg-bad-py3-none-any.whl"} {
		if _, _, _, e := pythonDistribution(filename); e == nil {
			t.Fatal("invalid distribution coordinate accepted", filename)
		}
	}
}
func FuzzPythonArchive(f *testing.F) {
	f.Add(pythonWheelFixture(f, "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\n\n", nil))
	f.Add([]byte("not an archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		core, e := inspectPythonDistribution(context.Background(), bytes.NewReader(data), int64(len(data)), "pkg-1.0-py3-none-any.whl", pythonArchiveBudget{64 << 10, 32, 4096})
		if e == nil && (core.Name != "pkg" || core.Version != "1.0") {
			t.Fatal("archive coordinate escaped validation")
		}
	})
}
