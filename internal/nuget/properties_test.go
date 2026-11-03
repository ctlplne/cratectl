// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNuspecPropertiesPreserveDeclaredTextAndFirstNonemptyLeaf(t *testing.T) {
	raw := `<package><metadata><id>Owned.Package</id><version>01.0</version><authors></authors><AUTHORS>  Alice &amp; Bob  </AUTHORS><authors>later</authors><description><b>not a leaf</b></description><Description><![CDATA[<img src=x onerror=unused()>]]></Description><x:summary xmlns:x="urn:foreign">foreign scalar</x:summary><tags>alpha beta</tags><projectUrl>https://example.invalid/never-fetched</projectUrl><license type="expression">MIT OR Apache-2.0</license><unknown>opaque</unknown></metadata></package>`
	properties, e := ParseNuspecProperties(context.Background(), []byte(raw))
	want := map[string]string{"id": "Owned.Package", "version": "01.0", "authors": "  Alice & Bob  ", "description": "<img src=x onerror=unused()>", "summary": "foreign scalar", "tags": "alpha beta", "projecturl": "https://example.invalid/never-fetched", "license": "MIT OR Apache-2.0"}
	if e != nil || !reflect.DeepEqual(properties.Values, want) || properties.Identity.VersionKey != "1.0.0" {
		t.Fatal("declared scalar metadata changed", properties, e)
	}
	encoded := `<?xml version="1.0" encoding="utf-16"?>` + raw
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		got, e := ParseNuspecProperties(context.Background(), nuspecUTF16(encoded, order, true))
		if e != nil || !reflect.DeepEqual(got, properties) {
			t.Fatal("properties changed across XML encoding", got, e)
		}
	}
}

func TestNuspecPropertiesWhitespaceAndBounds(t *testing.T) {
	for _, tc := range []struct{ fields, title string }{
		{`<title>   </title><title>next</title>`, "next"},
		{`<title><![CDATA[   ]]></title><title>next</title>`, "   "},
		{`<title>&#32;</title><title>next</title>`, " "},
		{`<title xml:space="preserve">   </title><title>next</title>`, "   "},
		{`<title xml:space="default">  value  </title>`, "  value  "},
	} {
		raw := `<package><metadata><id>Owned.Package</id><version>1</version>` + tc.fields + `</metadata></package>`
		got, e := ParseNuspecProperties(context.Background(), []byte(raw))
		if e != nil || got.Values["title"] != tc.title {
			t.Fatal("whitespace changed", tc.fields, got.Values, e)
		}
	}
	for _, fields := range []string{`<title xml:space="invalid">value</title>`, `<description>` + strings.Repeat("a", MaxNuspecPropertyBytes+1) + `</description>`} {
		raw := `<package><metadata><id>Owned.Package</id><version>1</version>` + fields + `</metadata></package>`
		got, e := ParseNuspecProperties(context.Background(), []byte(raw))
		if !errors.Is(e, ErrNuspec) || got.Values != nil || got.Identity != (NuspecIdentity{}) {
			t.Fatal("invalid or oversized properties returned partial metadata", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := ParseNuspecProperties(ctx, []byte(nuspecFixture)); !errors.Is(e, context.Canceled) || got.Values != nil {
		t.Fatal("cancelled property read returned metadata", e)
	}
}

func FuzzNuspecProperties(f *testing.F) {
	f.Add([]byte(nuspecFixture))
	f.Add([]byte(`<package><metadata><id>Owned.Package</id><version>1</version><TITLE><![CDATA[   ]]></TITLE><title>ignored</title></metadata></package>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, e := ParseNuspecProperties(context.Background(), raw)
		if e != nil {
			if got.Values != nil || got.Identity != (NuspecIdentity{}) {
				t.Fatal("failed property parser produced partial metadata")
			}
			return
		}
		if len(got.Values) > len(nuspecPropertyNames) {
			t.Fatal("property count budget")
		}
		for key, value := range got.Values {
			if propertyName(key) != key || value == "" || len(value) > MaxNuspecPropertyBytes {
				t.Fatal("property key or value escaped its budget")
			}
		}
	})
}
