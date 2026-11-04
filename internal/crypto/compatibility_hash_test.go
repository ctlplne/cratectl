// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"encoding/hex"
	"testing"
)

func TestCompatibilitySHA384Vector(t *testing.T) {
	h := CompatibilityHash("sha384")
	if h == nil {
		t.Fatal("documented Ivy SHA-384 checksum is unsupported")
	}
	for _, part := range []string{"a", "b", "c"} {
		_, _ = h.Write([]byte(part))
	}
	want := "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Fatalf("SHA-384 compatibility vector: got %s", got)
	}
}
