// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"strings"
	"testing"
)

func TestMaterializedLifecyclePathBoundary(t *testing.T) {
	for _, p := range []string{"", ".", "..", "../pkg", "/pkg", "pkg/../other", "pkg//file", "pkg\\file", "pkg\nfile", "pkg\x00file", "pkg\x7ffile", string([]byte{0xff}), strings.Repeat("a", 2049)} {
		if materializedLifecyclePath(p) {
			t.Fatalf("unsafe or oversized lifecycle subject accepted: %q", p)
		}
	}
	for _, p := range []string{"org/example/package/1.0/package-1.0.jar", "@owned/pkg/-/@owned/pkg-1.0.0.tgz", "owned_package-1.0-py3-none-any.whl", "owned files/λ.bin", strings.Repeat("a", 2048)} {
		if !materializedLifecyclePath(p) {
			t.Fatalf("bounded native subject rejected: %q", p)
		}
	}
}
