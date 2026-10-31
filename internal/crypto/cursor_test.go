// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCursorConfidentialityScopeAndTampering(t *testing.T) {
	secret, _ := Token()
	key, e := ParseCursorKey(secret)
	if e != nil {
		t.Fatal(e)
	}
	position := "private/manifests/sha256:" + strings.Repeat("a", 64)
	a, e := key.Seal("tenant/actor/repo/search", position, true)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := key.Seal("tenant/actor/repo/search", position, true)
	if a == b {
		t.Fatal("nonce reused")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(a, "p1."))
	if bytes.Contains(raw, []byte(position)) {
		t.Fatal("hidden path is plaintext")
	}
	got, before, e := key.Open("tenant/actor/repo/search", a)
	if e != nil || got != position || !before {
		t.Fatal("roundtrip failed")
	}
	for _, scope := range []string{"other-tenant/actor/repo/search", "tenant/other/repo/search", "tenant/actor/other/search", "tenant/actor/repo/other"} {
		if _, _, e = key.Open(scope, a); e == nil {
			t.Fatal("scope substitution accepted")
		}
	}
	raw[len(raw)-1] ^= 1
	if _, _, e = key.Open("tenant/actor/repo/search", "p1."+base64.RawURLEncoding.EncodeToString(raw)); e == nil {
		t.Fatal("tampering accepted")
	}
	rotated, _ := Token()
	other, _ := ParseCursorKey(rotated)
	if _, _, e = other.Open("tenant/actor/repo/search", a); e == nil {
		t.Fatal("rotated key accepted old cursor")
	}
	for _, token := range []string{"", "p2.abc", "p1.", strings.Repeat("x", 3001), "p1.%%%"} {
		if _, _, e = key.Open("scope", token); e == nil {
			t.Fatal("malformed cursor accepted")
		}
	}
}
func FuzzCursorRejectsMalformedInput(f *testing.F) {
	secret, _ := Token()
	key, _ := ParseCursorKey(secret)
	f.Add("p1.bad")
	f.Add("")
	f.Fuzz(func(t *testing.T, v string) { _, _, _ = key.Open("owned-scope", v) })
}

func TestCursorBoundsSupportGlobalHoldPositions(t *testing.T) {
	secret, _ := Token()
	key, err := ParseCursorKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	position := strings.Repeat("r", 63) + "\n" + strings.Repeat("p", 2048)
	token, err := key.Seal("owned-hold-page", position, false)
	if err != nil || len(token) > 3000 {
		t.Fatal("bounded global position unavailable", err)
	}
	got, before, err := key.Open("owned-hold-page", token)
	if err != nil || got != position || before {
		t.Fatal("maximum position failed round trip", err)
	}
	if _, err = key.Seal("owned-hold-page", position+"x", false); err == nil {
		t.Fatal("oversized position accepted")
	}
	if _, _, err = key.Open("other-tenant", token); err == nil {
		t.Fatal("maximum position lost scope binding")
	}
}
