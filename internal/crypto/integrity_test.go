// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func sourceTestSum(algorithm, payload string) string {
	h := CompatibilityHash(algorithm)
	io.WriteString(h, payload)
	return algorithm + "-" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}
func TestStrongestSourceIntegrity(t *testing.T) {
	good := sourceTestSum("sha512", "payload")
	wrong := sourceTestSum("sha512", "wrong")
	weak := sourceTestSum("sha256", "payload")
	for _, tc := range []struct {
		raw    string
		accept bool
	}{{good, true}, {wrong + " " + weak, false}, {wrong + " " + good, true}, {weak + " " + good, true}, {"sha1024-ignored " + good, true}} {
		pin, e := ParseSourceIntegrity(tc.raw, "", false)
		if e != nil {
			t.Fatal(e)
		}
		if (pin.Verify(strings.NewReader("payload")) == nil) != tc.accept {
			t.Fatal("weaker hash substituted for strongest source pin", tc.raw)
		}
	}
	if _, e := ParseSourceIntegrity("", SHA1([]byte("payload")), false); e == nil {
		t.Fatal("legacy integrity silently enabled")
	}
	pin, e := ParseSourceIntegrity("", SHA1([]byte("payload")), true)
	if e != nil || pin.Verify(strings.NewReader("payload")) != nil {
		t.Fatal("explicit legacy source failed", e)
	}
	for _, raw := range []string{"", "sha512-bad", strings.Repeat("x", 4097), strings.Repeat(good+" ", 33)} {
		if _, e := ParseSourceIntegrity(raw, "", false); e == nil {
			t.Fatal("invalid source integrity accepted")
		}
	}
}
func FuzzSourceIntegrity(f *testing.F) {
	f.Add(Integrity([]byte("fixture")))
	f.Add("sha512-bad")
	f.Fuzz(func(t *testing.T, raw string) {
		pin, e := ParseSourceIntegrity(raw, "", false)
		if e == nil {
			again, e := ParseSourceIntegrity(pin.Canonical, "", false)
			if e != nil || again.Canonical != pin.Canonical {
				t.Fatal("source pin did not canonicalize")
			}
			_ = pin.Verify(bytes.NewBufferString("fixture"))
		}
	})
}
