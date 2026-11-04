// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/ziparchive"
	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

var testCoordinate = Coordinate{"go.cratectl.invalid/Owned/app", "v1.2.3"}
var testLimits = ziparchive.Limits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64}

type fixtureFile struct {
	name, body string
	mode       fs.FileMode
}

func moduleFixture(t testing.TB, c Coordinate, files []fixtureFile) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, f := range files {
		h := &zip.FileHeader{Name: c.Module + "@" + c.Version + "/" + f.name, Method: zip.Deflate}
		mode := f.mode
		if mode == 0 {
			mode = 0600
		}
		h.SetMode(mode)
		w, e := z.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(f.body)); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func baseFiles(c Coordinate) []fixtureFile {
	return []fixtureFile{{name: "go.mod", body: "// exact owned bytes\nmodule " + c.Module + "\n\ngo 1.26\n\nrequire go.cratectl.invalid/dependency v1.0.0\n"}, {name: "owned.go", body: "package owned\n// opaque package bytes; never compiled or executed\n"}}
}
func inspect(data []byte, c Coordinate) (Archive, error) {
	return InspectArchive(context.Background(), bytes.NewReader(data), int64(len(data)), c, testLimits)
}

func TestNativeRequestIdentityAndAliases(t *testing.T) {
	cases := map[string]Request{
		"go.cratectl.invalid/!owned/app/@v/v1.2.3.zip":                        {testCoordinate, "zip"},
		"go.cratectl.invalid/!owned/app/@v/v1.2.3.mod":                        {testCoordinate, "mod"},
		"go.cratectl.invalid/!owned/app/@v/v1.2.3.info":                       {testCoordinate, "info"},
		"go.cratectl.invalid/!owned/app/@v/list":                              {Coordinate{Module: testCoordinate.Module}, "list"},
		"go.cratectl.invalid/!owned/app/@latest":                              {Coordinate{Module: testCoordinate.Module}, "latest"},
		"go.cratectl.invalid/app/v2/@v/v2.1.0-!alpha.info":                    {Coordinate{"go.cratectl.invalid/app/v2", "v2.1.0-Alpha"}, "info"},
		"go.cratectl.invalid/app/@v/v1.0.1-0.20260102030405-0123456789ab.mod": {Coordinate{"go.cratectl.invalid/app", "v1.0.1-0.20260102030405-0123456789ab"}, "mod"},
	}
	for p, want := range cases {
		got, e := ParseRequest(p)
		if e != nil || got != want {
			t.Errorf("%s: %+v %v", p, got, e)
		}
	}
	for _, p := range []string{"go.cratectl.invalid/Owned/app/@v/v1.2.3.zip", "go.cratectl.invalid/%4fwned/app/@v/v1.2.3.zip", "go.cratectl.invalid/app/@v/latest", "go.cratectl.invalid/app/@v/v1.2.zip", "go.cratectl.invalid/app/v2/@v/v1.0.0.zip", "go.cratectl.invalid/app/@v/v2.0.0.zip", "go.cratectl.invalid/app/@v/v1.2.3+alias.zip", "go.cratectl.invalid/app/@v/v1.2.3.zip/extra", "go.cratectl.invalid/app/@v/v1.2.3.zip?query", "go.cratectl.invalid/app/../app/@v/list", "go.cratectl.invalid/!!app/@v/list", "go.cratectl.invalid/app/@v/v1.2.3.ZIP", strings.Repeat("a", 2049)} {
		if got, e := ParseRequest(p); !errors.Is(e, ErrModule) || got != (Request{}) {
			t.Errorf("accepted alias %q %+v %v", p, got, e)
		}
	}
}
func TestVersionInfoRetainsCallerInstant(t *testing.T) {
	got, e := VersionInfo(testCoordinate, "2026-01-02T04:04:05+01:00")
	if e != nil || string(got) != `{"Version":"v1.2.3","Time":"2026-01-02T03:04:05Z"}` {
		t.Fatal(string(got), e)
	}
	for _, instant := range []string{"", "0001-01-01T00:00:00Z", "2026-01-02", "2026-01-02T03:04:05Z\n", strings.Repeat("x", 65)} {
		if _, e := VersionInfo(testCoordinate, instant); e == nil {
			t.Errorf("accepted %q", instant)
		}
	}
	if _, e := VersionInfo(Coordinate{"go.cratectl.invalid/app/v2", "v1.0.0"}, "2026-01-02T03:04:05Z"); e == nil {
		t.Fatal("invalid path major")
	}
}
func TestArchiveRetainsExactGoModAndAgreesWithOfficialChecker(t *testing.T) {
	for _, c := range []Coordinate{testCoordinate, {"go.cratectl.invalid/app/v2", "v2.0.0"}, {"go.cratectl.invalid/app", "v1.0.1-0.20260102030405-0123456789ab"}} {
		files := baseFiles(c)
		files = append(files, fixtureFile{name: "assets/value%owned.txt", body: "inert"}, fixtureFile{name: "assets/unicode-Σ.txt", body: "inert"})
		data := moduleFixture(t, c, files)
		got, e := inspect(data, c)
		if e != nil || !bytes.Equal(got.GoMod, []byte(files[0].body)) || got.Files != 4 {
			t.Fatalf("%+v %v", got, e)
		}
		p := t.TempDir() + "/owned.zip"
		if e = os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		checked, e := modzip.CheckZip(module.Version{Path: c.Module, Version: c.Version}, p)
		if e != nil || len(checked.Valid) != got.Files {
			t.Fatal("official module ZIP checker differs", checked, e)
		}
	}
}
func TestArchiveRejectsCoordinateMetadataAndPathSubstitution(t *testing.T) {
	cases := map[string][]fixtureFile{
		"missing go.mod":          {{name: "owned.go", body: "opaque"}},
		"wrong module":            {{name: "go.mod", body: "module go.cratectl.invalid/other\n"}},
		"duplicate module":        {{name: "go.mod", body: "module go.cratectl.invalid/Owned/app\nmodule go.cratectl.invalid/other\n"}},
		"invalid directive":       {{name: "go.mod", body: "module \"unterminated\n"}},
		"case go.mod":             {{name: "Go.Mod", body: "module " + testCoordinate.Module + "\n"}},
		"nested go.mod":           append(baseFiles(testCoordinate), fixtureFile{name: "nested/go.mod", body: "module other\n"}),
		"duplicate":               append(baseFiles(testCoordinate), fixtureFile{name: "owned.go", body: "different"}),
		"implicit directory case": append(baseFiles(testCoordinate), fixtureFile{name: "Dir/a", body: "a"}, fixtureFile{name: "dir/b", body: "b"}),
		"file parent":             append(baseFiles(testCoordinate), fixtureFile{name: "owned.go/child", body: "x"}),
		"traversal":               append(baseFiles(testCoordinate), fixtureFile{name: "../escape", body: "x"}),
		"reserved windows name":   append(baseFiles(testCoordinate), fixtureFile{name: "CON.txt", body: "x"}),
		"symlink":                 append(baseFiles(testCoordinate), fixtureFile{name: "link", body: "owned.go", mode: fs.ModeSymlink | 0600}),
		"oversized go.mod":        {{name: "go.mod", body: strings.Repeat("/", MaxGoMod+1)}},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			got, e := inspect(moduleFixture(t, testCoordinate, files), testCoordinate)
			if e == nil || !reflect.DeepEqual(got, Archive{}) {
				t.Fatal("accepted invalid module or partial identity", got, e)
			}
		})
	}
	c := testCoordinate
	c.Module = "go.cratectl.invalid/other"
	if got, e := inspect(moduleFixture(t, c, baseFiles(c)), testCoordinate); e == nil || !reflect.DeepEqual(got, Archive{}) {
		t.Fatal("ZIP prefix substitution", e)
	}
}
func TestArchiveBudgetsPhysicalCountChecksumAndCancellation(t *testing.T) {
	data := moduleFixture(t, testCoordinate, baseFiles(testCoordinate))
	for _, limits := range []ziparchive.Limits{{CompressedBytes: 1, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64}, {CompressedBytes: 2 << 20, ExpandedBytes: 1, DirectoryBytes: 128 << 10, Files: 64}, {CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 1, Files: 64}, {CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 1}} {
		if got, e := InspectArchive(context.Background(), bytes.NewReader(data), int64(len(data)), testCoordinate, limits); e == nil || !reflect.DeepEqual(got, Archive{}) {
			t.Fatal("budget ignored", got, e)
		}
	}
	forged := bytes.Clone(data)
	end := bytes.LastIndex(forged, []byte{'P', 'K', 5, 6})
	binary.LittleEndian.PutUint16(forged[end+8:], 1)
	binary.LittleEndian.PutUint16(forged[end+10:], 1)
	if got, e := inspect(forged, testCoordinate); e == nil || !reflect.DeepEqual(got, Archive{}) {
		t.Fatal("forged physical count", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := InspectArchive(ctx, bytes.NewReader(data), int64(len(data)), testCoordinate, testLimits); !errors.Is(e, context.Canceled) || !reflect.DeepEqual(got, Archive{}) {
		t.Fatal("cancellation", got, e)
	}
	// Change payload bytes without changing headers: every opaque stream is checked.
	corrupted := bytes.Clone(data)
	corrupted[45] ^= 0xff
	if got, e := inspect(corrupted, testCoordinate); e == nil || !reflect.DeepEqual(got, Archive{}) {
		t.Fatal("corrupt payload", got, e)
	}
}
func FuzzNativeRequest(f *testing.F) {
	for _, s := range []string{"go.cratectl.invalid/!owned/app/@v/v1.2.3.zip", "go.cratectl.invalid/app/@latest", "go.cratectl.invalid/app/@v/list"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got, e := ParseRequest(p)
		if e != nil {
			return
		}
		if got.Module == "" || len(got.Module) > MaxModulePath {
			t.Fatal(got)
		}
		if got.Version != "" {
			if _, e := Canonical(got.Module, got.Version); e != nil {
				t.Fatal(got, e)
			}
		}
	})
}
func FuzzModuleArchive(f *testing.F) {
	f.Add(moduleFixture(f, testCoordinate, baseFiles(testCoordinate)))
	f.Add([]byte("not a ZIP"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > int(testLimits.CompressedBytes) {
			return
		}
		got, e := inspect(data, testCoordinate)
		if e != nil {
			if !reflect.DeepEqual(got, Archive{}) {
				t.Fatal("partial identity")
			}
			return
		}
		if len(got.GoMod) > MaxGoMod || got.Files > testLimits.Files || got.ExpandedBytes > testLimits.ExpandedBytes {
			t.Fatal("budget escaped")
		}
	})
}

func TestPseudoVersionInfoBindsItsTimestamp(t *testing.T) {
	c := Coordinate{"go.cratectl.invalid/app", "v1.0.1-0.20260102030405-0123456789ab"}
	if _, e := VersionInfo(c, "2026-01-02T03:04:05Z"); e != nil {
		t.Fatal(e)
	}
	if _, e := VersionInfo(c, "2026-01-02T03:04:06Z"); e == nil {
		t.Fatal("pseudo-version timestamp mismatch")
	}
	c.Version = "v1.0.1-0.20261302030405-0123456789ab"
	if _, e := VersionInfo(c, "2026-01-02T03:04:05Z"); e == nil {
		t.Fatal("invalid pseudo-version date")
	}
}
