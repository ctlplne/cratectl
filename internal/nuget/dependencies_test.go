// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func dependencyDocument(body string) []byte {
	return []byte(`<package><metadata><id>Owned.Package</id><version>1.0+owned</version>` + body + `</metadata></package>`)
}

func TestNuspecDependencyGroupsPreserveDeclarations(t *testing.T) {
	raw := dependencyDocument(`<dependencies><dependency id="ignored/invalid" version="invalid"/><group targetFramework="net10.0"><dependency id="Owned.Dependency" version="1.2*" include="runtime,Build,runtime" exclude="analyzers"/><dependency id="Owned.Any"/></group><group targetFramework=".NETStandard2.0"/></dependencies>`)
	got, e := ParseNuspecDependencies(context.Background(), raw)
	if e != nil || len(got.Groups) != 2 || len(got.Groups[0].Dependencies) != 2 || len(got.Groups[1].Dependencies) != 0 {
		t.Fatal("group selection or empty group changed", got, e)
	}
	group, dep := got.Groups[0], got.Groups[0].Dependencies[0]
	if group.TargetFramework != "net10.0" || dep.ID != "Owned.Dependency" || dep.IDKey != "owned.dependency" || dep.RawRange != "1.2*" || dep.Range.Min != "1.20.0" || dep.Range.FloatString != "1.*" || dep.Include != "runtime,Build,runtime" || dep.Exclude != "analyzers" {
		t.Fatal("raw declaration or parsed floor lost", dep)
	}
	if any := got.Groups[0].Dependencies[1]; any.RawRange != "" || any.Range.Normalized != "(, )" {
		t.Fatal("absent range did not remain explicit All", any)
	}
	encoded := `<?xml version="1.0" encoding="utf-16"?>` + string(raw)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		other, e := ParseNuspecDependencies(context.Background(), nuspecUTF16(encoded, order, true))
		if e != nil || !reflect.DeepEqual(got, other) {
			t.Fatal("dependency declarations changed with encoding", e)
		}
	}
}

func TestNuspecDependencyNamespaceCaseAndLegacySelection(t *testing.T) {
	for _, body := range []string{
		`<Dependencies><dependency id="ignored/invalid"/></Dependencies>`,
		`<dependencies xmlns="urn:foreign"><dependency id="ignored/invalid"/></dependencies>`,
		`<dependencies><x:dependency xmlns:x="urn:foreign" id="ignored/invalid"/></dependencies>`,
	} {
		got, e := ParseNuspecDependencies(context.Background(), dependencyDocument(body))
		if e != nil || len(got.Groups) != 0 {
			t.Fatal("unselected names became dependencies", got, e)
		}
	}
	for _, raw := range []string{
		`<package><files><dependencies><dependency id="ignored/invalid"/></dependencies></files><metadata><id>Owned.Package</id><version>1</version></metadata></package>`,
		`<package><metadata><id>Owned.Package</id><version>1</version><dependencies><dependency id="ignored/invalid"/><group/></dependencies></metadata></package>`,
	} {
		got, e := ParseNuspecDependencies(context.Background(), []byte(raw))
		if e != nil || len(got.Groups) > 1 || len(got.Groups) == 1 && len(got.Groups[0].Dependencies) != 0 {
			t.Fatal("unselected legacy data was validated or exposed", e)
		}
	}
	got, e := ParseNuspecDependencies(context.Background(), dependencyDocument(`<dependencies><dependency id="Owned.A" version="[1,2)"/></dependencies><dependencies><dependency id="Owned.B" version=""/></dependencies>`))
	if e != nil || len(got.Groups) != 1 || len(got.Groups[0].Dependencies) != 2 || got.Groups[0].TargetFramework != "" {
		t.Fatal("legacy nodes did not combine in declaration order", e)
	}
	// The metadata element's effective default namespace selects dependency
	// nodes, independently of the namespace bound to its explicit prefix.
	raw := `<p:package xmlns:p="urn:owned"><p:metadata xmlns="urn:deps"><p:id>Owned.Package</p:id><p:version>1</p:version><dependencies><group targetFramework="net10.0"><dependency id="Owned.A" version="1"/></group></dependencies></p:metadata></p:package>`
	got, e = ParseNuspecDependencies(context.Background(), []byte(raw))
	if e != nil || len(got.Groups) != 1 || len(got.Groups[0].Dependencies) != 1 {
		t.Fatal("effective dependency namespace lost", e)
	}
}

func TestNuspecDependencyAttributesNormalizeLiteralWhitespace(t *testing.T) {
	raw := dependencyDocument("<dependencies><group targetFramework=\"net10.0\"><dependency id='Owned.A' version='1.0' include=\"a\tb\r\nc&#x9;d\" exclude='x\ny'/></group></dependencies>")
	original := append([]byte(nil), raw...)
	got, e := ParseNuspecDependencies(context.Background(), raw)
	if e != nil || len(got.Groups) != 1 || len(got.Groups[0].Dependencies) != 1 {
		t.Fatal(e)
	}
	dep := got.Groups[0].Dependencies[0]
	if dep.Include != "a b c\td" || dep.Exclude != "x y" || !bytes.Equal(raw, original) {
		t.Fatal("literal/reference attribute distinction or original bytes changed", dep)
	}
	text := "<description><![CDATA[<x a='a\tb'>]]></description>"
	properties, e := ParseNuspecProperties(context.Background(), dependencyDocument(text))
	if e != nil || properties.Values["description"] != "<x a='a\tb'>" {
		t.Fatal("CDATA text was treated as attributes", e)
	}
}

func TestNuspecDependenciesFailWithoutPartialResults(t *testing.T) {
	for _, body := range []string{
		`<dependencies><dependency id="Owned.A" version="v1"/></dependencies>`,
		`<dependencies><dependency id="Owned.A" version=" "/></dependencies>`,
		`<dependencies><dependency id="invalid/id" version="1"/></dependencies>`,
		`<dependencies><dependency version="1"/></dependencies>`,
		`<dependencies><group targetFramework="` + strings.Repeat("a", MaxNuspecDependencyFieldBytes+1) + `"/></dependencies>`,
		`<dependencies>` + strings.Repeat(`<group/>`, MaxNuspecDependencyGroups+1) + `</dependencies>`,
		`<dependencies>` + strings.Repeat(`<dependency id="A"/>`, MaxNuspecDependencies+1) + `</dependencies>`,
	} {
		got, e := ParseNuspecDependencies(context.Background(), dependencyDocument(body))
		if e == nil || got.Groups != nil || got.Identity != (NuspecIdentity{}) {
			t.Fatal("invalid active metadata yielded partial dependencies", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, e := ParseNuspecDependencies(ctx, dependencyDocument(`<dependencies/>`))
	if !errors.Is(e, context.Canceled) || got.Groups != nil {
		t.Fatal("cancelled dependency read returned data", e)
	}
}

func FuzzNuspecDependencies(f *testing.F) {
	f.Add(dependencyDocument(`<dependencies><group targetFramework="net10.0"><dependency id="Owned.Dependency" version="[1,2)"/></group></dependencies>`))
	f.Add(dependencyDocument(`<dependencies><dependency id="ignored/invalid"/><group/></dependencies>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, e := ParseNuspecDependencies(context.Background(), raw)
		if e != nil {
			if got.Groups != nil || got.Identity != (NuspecIdentity{}) {
				t.Fatal("failed parse returned partial dependencies")
			}
			return
		}
		if len(got.Groups) > MaxNuspecDependencyGroups {
			t.Fatal("group budget escaped")
		}
		count := 0
		for _, group := range got.Groups {
			count += len(group.Dependencies)
			for _, dep := range group.Dependencies {
				key, e := IDKey(dep.ID)
				if e != nil || key != dep.IDKey || dep.Range.Normalized == "" {
					t.Fatal("invalid dependency result")
				}
			}
		}
		if count > MaxNuspecDependencies {
			t.Fatal("dependency budget escaped")
		}
	})
}
