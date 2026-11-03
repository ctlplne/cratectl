// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

const nuspecFixture = `<?xml version="1.0" encoding="utf-8"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>Cratectl.Example</id><version>01.0.0.0-Alpha.1+build.12</version><authors>Owned fixture</authors><description>Opaque metadata only</description><dependencies><group targetFramework="net10.0"><dependency id="Cratectl.Dependency" version="[1.0,2.0)" /></group></dependencies></metadata></package>`

func nuspecUTF16(value string, order binary.ByteOrder, bom bool) []byte {
	var raw []byte
	if bom {
		if order == binary.LittleEndian {
			raw = []byte{0xff, 0xfe}
		} else {
			raw = []byte{0xfe, 0xff}
		}
	}
	for _, unit := range utf16.Encode([]rune(value)) {
		var word [2]byte
		order.PutUint16(word[:], unit)
		raw = append(raw, word[:]...)
	}
	return raw
}

func TestNuspecIdentityAcrossNativeXMLEncodings(t *testing.T) {
	utf16XML := strings.Replace(nuspecFixture, "utf-8", "utf-16", 1)
	for name, raw := range map[string][]byte{
		"UTF8": []byte(nuspecFixture), "UTF8 BOM": append([]byte{0xef, 0xbb, 0xbf}, []byte(nuspecFixture)...),
		"UTF16LE": nuspecUTF16(utf16XML, binary.LittleEndian, true), "UTF16BE": nuspecUTF16(utf16XML, binary.BigEndian, true),
		"UTF16LE signature": nuspecUTF16(utf16XML, binary.LittleEndian, false), "UTF16BE signature": nuspecUTF16(utf16XML, binary.BigEndian, false),
	} {
		t.Run(name, func(t *testing.T) {
			identity, err := ParseNuspecIdentity(context.Background(), raw)
			if err != nil || identity.ID != "Cratectl.Example" || identity.VersionKey != "1.0.0-alpha.1" || identity.RawVersion != "01.0.0.0-Alpha.1+build.12" {
				t.Fatal("identity changed across encoding", identity, err)
			}
		})
	}
	legacy := strings.Replace(nuspecFixture, "Cratectl.Example", "Cratectl.Ünicode", 1)
	if got, err := ParseNuspecIdentity(context.Background(), []byte(legacy)); err != nil || got.ID != "Cratectl.Ünicode" {
		t.Fatal("legacy display identity lost", got, err)
	}
}

func TestNuspecRejectsAmbiguousAndUnboundedIdentity(t *testing.T) {
	for name, raw := range map[string][]byte{
		"duplicate id":           []byte(strings.Replace(nuspecFixture, "</id>", "</id><id>Other</id>", 1)),
		"case alias":             []byte(strings.Replace(nuspecFixture, "</id>", "</id><ID>Other</ID>", 1)),
		"namespace shadow":       []byte(strings.Replace(nuspecFixture, "<id>", `<id xmlns="https://foreign.invalid">`, 1)),
		"nested identity":        []byte(strings.Replace(nuspecFixture, "Cratectl.Example", "<value>Cratectl.Example</value>", 1)),
		"duplicate attributes":   []byte(strings.Replace(nuspecFixture, "<id>", `<id attribute="one" attribute="two">`, 1)),
		"multiple roots":         []byte(nuspecFixture + nuspecFixture),
		"DTD":                    []byte(strings.Replace(nuspecFixture, "<package", `<!DOCTYPE package [<!ENTITY external SYSTEM "file:///private">]><package`, 1)),
		"path ID":                []byte(strings.Replace(nuspecFixture, "Cratectl.Example", "../private", 1)),
		"empty ID":               []byte(strings.Replace(nuspecFixture, "Cratectl.Example", "", 1)),
		"oversized ID":           []byte(strings.Replace(nuspecFixture, "Cratectl.Example", strings.Repeat("a", 101), 1)),
		"invalid version":        []byte(strings.Replace(nuspecFixture, "01.0.0.0-Alpha.1+build.12", "1.0.*", 1)),
		"invalid UTF8":           append([]byte(nuspecFixture), 0xff),
		"odd UTF16":              append(nuspecUTF16(strings.Replace(nuspecFixture, "utf-8", "utf-16", 1), binary.LittleEndian, true), 0),
		"unpaired surrogate":     {0xff, 0xfe, 0x00, 0xd8},
		"encoding contradiction": nuspecUTF16(nuspecFixture, binary.LittleEndian, true),
		"byte budget":            []byte(strings.Repeat(" ", MaxNuspecBytes+1)),
		"depth budget":           []byte(strings.Replace(nuspecFixture, "<dependencies>", strings.Repeat("<nested>", 40)+"<dependencies>", 1)),
		"token budget":           []byte(strings.Replace(nuspecFixture, "<dependencies>", strings.Repeat("<empty/>", 20000)+"<dependencies>", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			identity, err := ParseNuspecIdentity(context.Background(), raw)
			if !errors.Is(err, ErrNuspec) || identity != (NuspecIdentity{}) {
				t.Fatal("ambiguous input yielded identity", identity, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseNuspecIdentity(ctx, []byte(nuspecFixture)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled parser continued", err)
	}
}

func TestNuspecPreservesSDKDeclaredWhitespace(t *testing.T) {
	raw := []byte(`<package><metadata><id>  Cratectl.Trimmed  </id><version> 1.00.0 </version></metadata></package>`)
	identity, err := ParseNuspecIdentity(context.Background(), raw)
	if err != nil || identity.ID != "  Cratectl.Trimmed  " || identity.RawVersion != " 1.00.0 " || identity.VersionKey != "1.0.0" {
		t.Fatal("SDK-declared text was rewritten", identity, err)
	}
}

func FuzzNuspecIdentity(f *testing.F) {
	f.Add([]byte(nuspecFixture))
	f.Add(nuspecUTF16(strings.Replace(nuspecFixture, "utf-8", "utf-16", 1), binary.BigEndian, true))
	f.Add([]byte(`<package><metadata><id>Owned.Example</id><version>1</version></metadata></package>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		identity, err := ParseNuspecIdentity(context.Background(), raw)
		if err != nil {
			if identity != (NuspecIdentity{}) {
				t.Fatal("invalid manifest yielded partial identity")
			}
			return
		}
		if !validNuspecID(strings.TrimSpace(identity.ID)) {
			t.Fatal("accepted identity has unsafe ID")
		}
		key, err := VersionKey(identity.RawVersion)
		if err != nil || key != identity.VersionKey {
			t.Fatal("metadata version differs from its shared coordinate key")
		}
	})
}
