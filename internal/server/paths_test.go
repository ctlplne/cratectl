// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"testing"
)

func TestPaths(t *testing.T) {
	for _, p := range []string{"../x", "/x", "a/../b", "a//b", "a\\b", "x\x00", ".", "a/", "a/./x"} {
		if ValidPath(p) {
			t.Fatalf("accepted %q", p)
		}
	}
	for _, p := range []string{"a/b", "@scope/p/-/p-1.0.0.tgz", "pkg.whl"} {
		if !ValidPath(p) {
			t.Fatalf("rejected %q", p)
		}
	}
}
func FuzzPath(f *testing.F) {
	for _, p := range []string{"a/b", "../x", "a//b", "@s/a"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if ValidPath(p) && len(p) > 2048 {
			t.Fatal("unbounded coordinate")
		}
	})
}
func FuzzPythonNormalize(f *testing.F) {
	for _, p := range []string{"a._-b", "A_B", "pkg"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n := NormalizePython(p)
		if NormalizePython(n) != n {
			t.Fatal("normalization not idempotent")
		}
	})
}
