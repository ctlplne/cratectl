// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"bytes"
	"testing"
)

func FuzzNuspecXMLAttributeNormalization(f *testing.F) {
	f.Add([]byte("<group targetFramework='a\tb\r\nc&#x9;d'/>"))
	f.Add([]byte("<!-- <x a='a\tb'/> --><![CDATA[<x a='a\tb'/>]]><x a='a\tb'/>"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		original := append([]byte(nil), raw...)
		got, e := normalizeXMLAttributes(raw)
		if !bytes.Equal(raw, original) {
			t.Fatal("attribute normalization changed original bytes")
		}
		if e != nil {
			if got != nil {
				t.Fatal("invalid normalization returned partial bytes")
			}
			return
		}
		if len(got) > len(raw) {
			t.Fatal("normalization expanded the source")
		}
		again, e := normalizeXMLAttributes(got)
		if e != nil || !bytes.Equal(got, again) {
			t.Fatal("attribute normalization is not idempotent")
		}
	})
}
