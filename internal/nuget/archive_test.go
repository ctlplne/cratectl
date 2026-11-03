// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	cryptox "ctlplne.dev/cratectl/internal/crypto"
)

const archiveManifest = `<package><metadata><id>Cratectl.Archive</id><version>01.2.0-Alpha+owned</version><dependencies><group targetFramework="net10.0"><dependency id="Cratectl.Dependency" version="[1.0,2.0)"/></group></dependencies></metadata></package>`

type archiveFixtureEntry struct {
	name  string
	body  string
	mode  fs.FileMode
	extra []byte
}

var archiveTestLimits = ArchiveLimits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64}

func archiveFixtureCRC(data []byte) uint32 {
	h := cryptox.ZIPCRC32()
	h.Write(data)
	return h.Sum32()
}

func archiveFixture(t testing.TB, method uint16, entries []archiveFixtureEntry) []byte {
	t.Helper()
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	for _, entry := range entries {
		h := &zip.FileHeader{Name: entry.name, Method: method}
		h.Extra = entry.extra
		mode := entry.mode
		if mode == 0 {
			mode = 0o600
		}
		h.SetMode(mode)
		f, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.SetComment("Owned bounded archive fixture"); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func inspectArchiveBytes(ctx context.Context, data []byte, limits ArchiveLimits) (ArchiveIdentity, error) {
	return InspectArchive(ctx, bytes.NewReader(data), int64(len(data)), limits)
}

func rejectArchive(t *testing.T, data []byte, limits ArchiveLimits) {
	t.Helper()
	got, err := inspectArchiveBytes(context.Background(), data, limits)
	if !errors.Is(err, ErrArchive) || !reflect.DeepEqual(got, ArchiveIdentity{}) {
		t.Fatalf("archive rejection returned partial identity: %+v, %v", got, err)
	}
}

func TestArchiveIdentityRetainsManifestAndOpaquePayload(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		data := archiveFixture(t, method, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}, {name: "lib/", mode: fs.ModeDir | 0o755}, {name: "lib/net10.0/_._", body: "owned dependency-bearing package payload"}, {name: "build/Cratectl.Archive.targets", body: "opaque build metadata must never execute"}})
		out, err := inspectArchiveBytes(context.Background(), data, archiveTestLimits)
		if err != nil || out.Identity.ID != "Cratectl.Archive" || out.Identity.RawVersion != "01.2.0-Alpha+owned" || out.Identity.VersionKey != "1.2.0-alpha" || out.NuspecPath != "Cratectl.Archive.nuspec" || string(out.Nuspec) != archiveManifest || out.Files != 4 || out.ExpandedBytes != int64(len(archiveManifest)+len("owned dependency-bearing package payload")+len("opaque build metadata must never execute")) {
			t.Fatalf("archive identity differs: %+v, %v", out, err)
		}
		again, err := ParseNuspecIdentity(context.Background(), out.Nuspec)
		if err != nil || again != out.Identity {
			t.Fatal("manifest bytes do not bind identity", again, err)
		}
	}
}

func TestArchiveRejectsAmbiguousAndUnsafeEntries(t *testing.T) {
	manifest := archiveFixtureEntry{name: "Cratectl.Archive.nuspec", body: archiveManifest}
	cases := map[string][]archiveFixtureEntry{
		"missing":                     {{name: "lib/net10.0/_._"}},
		"nested only":                 {{name: "nested/Cratectl.Archive.nuspec", body: archiveManifest}},
		"Unicode extension alias":     {{name: "Cratectl.Archive.nuſpec", body: archiveManifest}},
		"two manifests":               {manifest, {name: "Other.nuspec", body: archiveManifest}},
		"duplicate exact":             {manifest, manifest},
		"case alias":                  {manifest, {name: "CRATECTL.ARCHIVE.NUSPEC", body: archiveManifest}},
		"file ancestor":               {manifest, {name: "lib", body: "opaque file"}, {name: "lib/net10.0/a.dll"}},
		"reverse ancestor":            {manifest, {name: "lib/net10.0/a.dll"}, {name: "LIB", body: "opaque file"}},
		"unicode normalization alias": {manifest, {name: "lib/é.txt"}, {name: "lib/e\u0301.txt"}},
		"symlink":                     {manifest, {name: "lib/alias", body: "../../outside", mode: fs.ModeSymlink | 0o777}},
		"device":                      {manifest, {name: "lib/device", mode: fs.ModeDevice | 0o600}},
		"bad manifest":                {{name: "Cratectl.Archive.nuspec", body: "<package>"}},
	}
	for _, name := range []string{"../outside", "/absolute", `lib\outside`, "C:/outside", "lib/./outside", "lib//outside", "lib/../outside", "lib/outside.", "lib/outside ", "lib/CON.txt", "lib/Lpt9", "lib/COM¹.txt", "lib/conout$", "lib/*.txt", "lib/%2e%2e/outside", "lib/\x00name", "lib/\xffname", strings.Repeat("d/", 64) + "file"} {
		cases[name] = []archiveFixtureEntry{manifest, {name: name, body: "opaque hostile member"}}
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) { rejectArchive(t, archiveFixture(t, zip.Store, entries), archiveTestLimits) })
	}
}

func TestArchiveUTF8NamesRequireTheirEncodingFlag(t *testing.T) {
	name := "lib/ü.txt"
	data := archiveFixture(t, zip.Store, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}, {name: name, body: "owned UTF8 path"}})
	if _, err := inspectArchiveBytes(context.Background(), data, archiveTestLimits); err != nil {
		t.Fatal("unambiguous UTF8 path rejected", err)
	}
	local := bytes.Index(data, []byte(name)) - 30
	central := bytes.LastIndex(data, []byte(name)) - 46
	for _, position := range []int{local + 6, central + 8} {
		binary.LittleEndian.PutUint16(data[position:], binary.LittleEndian.Uint16(data[position:])&^uint16(0x800))
	}
	rejectArchive(t, data, archiveTestLimits)
}

func TestArchiveRejectsAlternatePathAndUnsupportedExtraRecords(t *testing.T) {
	for _, extra := range [][]byte{{1, 0, 0, 0}, {0x75, 0x70, 0, 0}, {0x0d, 0, 0, 0}, {0x55, 0x54, 0xff, 0xff}, {1, 2, 3}} {
		data := archiveFixture(t, zip.Store, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest, extra: extra}})
		rejectArchive(t, data, archiveTestLimits)
	}
}

func TestArchiveAcceptsUnsignedTwelveByteDescriptor(t *testing.T) {
	data := archiveFixture(t, zip.Deflate, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}})
	end := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	directory := int(binary.LittleEndian.Uint32(data[end+16:]))
	if !bytes.Equal(data[directory-16:directory-12], []byte{'P', 'K', 7, 8}) {
		t.Fatal("fixture does not have signed sixteen-byte descriptor")
	}
	unsigned := append(bytes.Clone(data[:directory-16]), data[directory-12:]...)
	binary.LittleEndian.PutUint32(unsigned[end-4+16:], uint32(directory-4))
	got, err := inspectArchiveBytes(context.Background(), unsigned, archiveTestLimits)
	if err != nil || string(got.Nuspec) != archiveManifest {
		t.Fatal("bounded unsigned descriptor rejected", err)
	}
}

func TestArchiveAdmissionBudgetsAndPhysicalDirectoryCount(t *testing.T) {
	data := archiveFixture(t, zip.Deflate, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}, {name: "lib/net10.0/payload", body: strings.Repeat("x", 2<<20)}})
	for _, limits := range []ArchiveLimits{
		{},
		{CompressedBytes: int64(len(data)) - 1, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64},
		{CompressedBytes: 2 << 20, ExpandedBytes: 1 << 20, DirectoryBytes: 128 << 10, Files: 64},
		{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 45, Files: 64},
		{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 1},
		{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 17 << 20, Files: 64},
		{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 16385},
	} {
		rejectArchive(t, data, limits)
	}
	for _, count := range []uint16{0, 1, 65535} {
		forged := bytes.Clone(data)
		end := bytes.LastIndex(forged, []byte{'P', 'K', 5, 6})
		binary.LittleEndian.PutUint16(forged[end+8:], count)
		binary.LittleEndian.PutUint16(forged[end+10:], count)
		rejectArchive(t, forged, archiveTestLimits)
	}
	oversized := archiveFixture(t, zip.Deflate, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: strings.Repeat(" ", MaxNuspecBytes+1)}})
	rejectArchive(t, oversized, archiveTestLimits)
}

func TestArchiveRejectsHeaderSubstitutionAndAdditionalByteViews(t *testing.T) {
	data := archiveFixture(t, zip.Store, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}, {name: "lib/payload", body: "opaque package bytes"}})
	mutations := map[string]func([]byte) []byte{
		"local name":         func(b []byte) []byte { b[30] = 'X'; return b },
		"local flags":        func(b []byte) []byte { b[6] ^= 1; return b },
		"local method":       func(b []byte) []byte { b[8] = 99; return b },
		"local size":         func(b []byte) []byte { binary.LittleEndian.PutUint32(b[18:], 0xffffffff); return b },
		"payload crc":        func(b []byte) []byte { b[30+len("Cratectl.Archive.nuspec")+10] ^= 1; return b },
		"central encryption": func(b []byte) []byte { i := bytes.Index(b, []byte{'P', 'K', 1, 2}); b[i+8] |= 1; return b },
		"central offset overlap": func(b []byte) []byte {
			i := bytes.Index(b, []byte{'P', 'K', 1, 2})
			binary.LittleEndian.PutUint32(b[i+42:], 1)
			return b
		},
		"split archive": func(b []byte) []byte {
			i := bytes.LastIndex(b, []byte{'P', 'K', 5, 6})
			binary.LittleEndian.PutUint16(b[i+4:], 1)
			return b
		},
		"trailing":  func(b []byte) []byte { return append(b, []byte("unreferenced trailer")...) },
		"preamble":  func(b []byte) []byte { return append([]byte("unreferenced preamble"), b...) },
		"truncated": func(b []byte) []byte { return b[:len(b)-3] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) { rejectArchive(t, mutate(bytes.Clone(data)), archiveTestLimits) })
	}
}

func TestArchiveChecksCRCWhenDeclaredChecksumIsZero(t *testing.T) {
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	f, err := z.CreateRaw(&zip.FileHeader{Name: "Cratectl.Archive.nuspec", Method: zip.Store, CRC32: 0, CompressedSize64: uint64(len(archiveManifest)), UncompressedSize64: uint64(len(archiveManifest))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte(archiveManifest)); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if archiveFixtureCRC([]byte(archiveManifest)) == 0 {
		t.Fatal("fixture must have a nonzero actual checksum")
	}
	rejectArchive(t, data.Bytes(), archiveTestLimits)
}

func TestArchiveRejectsTrailingCompressedMemberBytes(t *testing.T) {
	var packed bytes.Buffer
	compressor, err := flate.NewWriter(&packed, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = compressor.Write([]byte(archiveManifest)); err != nil {
		t.Fatal(err)
	}
	if err = compressor.Close(); err != nil {
		t.Fatal(err)
	}
	packed.WriteString("unconsumed compressed-member trailer")
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	f, err := z.CreateRaw(&zip.FileHeader{Name: "Cratectl.Archive.nuspec", Method: zip.Deflate, CRC32: archiveFixtureCRC([]byte(archiveManifest)), CompressedSize64: uint64(packed.Len()), UncompressedSize64: uint64(len(archiveManifest))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(packed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	rejectArchive(t, data.Bytes(), archiveTestLimits)
}

type archiveCancellingReader struct {
	r      io.ReaderAt
	cancel context.CancelFunc
	calls  int
}

func (r *archiveCancellingReader) ReadAt(p []byte, offset int64) (int, error) {
	r.calls++
	if r.calls == 3 {
		r.cancel()
	}
	return r.r.ReadAt(p, offset)
}

func TestArchiveCancellationReturnsNoPartialIdentity(t *testing.T) {
	data := archiveFixture(t, zip.Deflate, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &archiveCancellingReader{r: bytes.NewReader(data), cancel: cancel}
	got, err := InspectArchive(ctx, r, int64(len(data)), archiveTestLimits)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, ArchiveIdentity{}) {
		t.Fatal("cancellation returned partial archive identity", got, err)
	}
}

func FuzzArchiveIdentity(f *testing.F) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		f.Add(archiveFixture(f, method, []archiveFixtureEntry{{name: "Cratectl.Archive.nuspec", body: archiveManifest}, {name: "lib/net10.0/_._", body: "owned immutable bytes"}}))
	}
	f.Add([]byte("not a ZIP archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		got, err := inspectArchiveBytes(context.Background(), data, archiveTestLimits)
		if err != nil {
			if !errors.Is(err, ErrArchive) && !errors.Is(err, ErrNuspec) {
				t.Fatal("unexpected archive error", err)
			}
			if !reflect.DeepEqual(got, ArchiveIdentity{}) {
				t.Fatal("invalid archive returned partial identity")
			}
			return
		}
		if got.Files < 1 || got.Files > archiveTestLimits.Files || got.ExpandedBytes > archiveTestLimits.ExpandedBytes || len(got.Nuspec) > MaxNuspecBytes || !archivePath(got.NuspecPath) {
			t.Fatal("accepted archive exceeded admission budgets")
		}
		identity, err := ParseNuspecIdentity(context.Background(), got.Nuspec)
		if err != nil || identity != got.Identity {
			t.Fatal("returned manifest bytes do not bind identity")
		}
	})
}
