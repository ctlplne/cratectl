// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"errors"
	"strings"
	"testing"
)

func TestIDKeyKeepsInvariantIdentityAndDeclaredTextSeparate(t *testing.T) {
	for raw, want := range map[string]string{"Cratectl.Library": "cratectl.library", "_Cratectl__Library": "_cratectl__library", "Cratectl.Ünicode": "cratectl.ünicode", "Cratectl.Σ": "cratectl.σ", "Cratectl.İD": "cratectl.İd", "Cratectl.ID": "cratectl.id", "Cratectl.ıD": "cratectl.ıd", "Cratectl.É": "cratectl.é", "Cratectl.E\u0301": "cratectl.e\u0301"} {
		key, err := IDKey(raw)
		if err != nil || key != want {
			t.Fatalf("ID %q key %q, %v; want %q", raw, key, err, want)
		}
	}
	i, _ := IDKey("Cratectl.ID")
	dotted, _ := IDKey("Cratectl.İD")
	dotless, _ := IDKey("Cratectl.ıD")
	if i == dotted || i == dotless || dotted == dotless {
		t.Fatal("distinct invariant ID keys merged")
	}
	composed, _ := IDKey("Cratectl.É")
	decomposed, _ := IDKey("Cratectl.E\u0301")
	if composed == decomposed {
		t.Fatal("Unicode normalization silently changed ID identity")
	}
}

func TestIDKeyRejectsUnsafeAndUnboundedCoordinates(t *testing.T) {
	for _, raw := range []string{"", " ", " Cratectl", "Cratectl ", "Cratectl\n", "Cratectl\r", "Cratectl\x00", "Cratectl\t", "../private", "Cratectl/Other", `Cratectl\Other`, "Cratectl%2eOther", "Cratectl..Other", "Cratectl.-Other", ".Cratectl", "Cratectl-", "Cratectl.𐐀", string([]byte{0xff}), strings.Repeat("a", 101), strings.Repeat("ü", 101), strings.Repeat("a", MaxIDBytes+1)} {
		key, err := IDKey(raw)
		if key != "" || !errors.Is(err, ErrID) {
			t.Fatal("unsafe ID returned a key", raw, key, err)
		}
	}
	if key, err := IDKey(strings.Repeat("Ü", 100)); err != nil || key != strings.Repeat("ü", 100) {
		t.Fatal("bounded legacy ID rejected", err)
	}
}

func FuzzIDKey(f *testing.F) {
	for _, raw := range []string{"Cratectl.Library", "_", "Cratectl.İD", "Cratectl.ID", "Cratectl.ıD", "Cratectl.E\u0301", "Cratectl/Other", "Cratectl\n"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		key, err := IDKey(raw)
		if err != nil {
			if key != "" || !errors.Is(err, ErrID) {
				t.Fatal("invalid ID yielded partial key")
			}
			return
		}
		if len(key) > MaxIDBytes || !validNuspecID(key) {
			t.Fatal("unsafe ID key")
		}
		again, err := IDKey(key)
		if err != nil || again != key {
			t.Fatal("ID key is not stable")
		}
	})
}
