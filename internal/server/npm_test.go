// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"testing"
)

func TestNativeNPMCoordinatesAndTags(t *testing.T) {
	for _, v := range []string{"1.0.0", "1.2.3-beta.1+build.7", "0.0.0+sha.a1"} {
		if !validNPMVersion(v) {
			t.Fatalf("valid semantic version rejected: %s", v)
		}
	}
	for _, v := range []string{"1.0", "01.2.3", "1.0.0-01", "1.2.3+", "v1.2.3"} {
		if validNPMVersion(v) {
			t.Fatalf("noncanonical version accepted: %s", v)
		}
	}
	for _, tag := range []string{"latest", "_canary", "qa+build", ".preview", "next-12"} {
		if !validNPMTag(tag) {
			t.Fatalf("valid tag rejected: %s", tag)
		}
	}
	for _, tag := range []string{"1.2", "*", "^1.0", "a/b", "a b", ".", "..", "%tag"} {
		if validNPMTag(tag) {
			t.Fatalf("invalid or range-like tag accepted: %s", tag)
		}
	}
	name, selector, ok := npmCoordinate("@scope/package/1.2.3-beta+build")
	if !ok || name != "@scope/package" || selector != "1.2.3-beta+build" {
		t.Fatal("scoped version endpoint parsed incorrectly")
	}
}
func FuzzNPMCoordinate(f *testing.F) {
	for _, p := range []string{"@scope/pkg", "pkg/latest", "pkg/../secret", "@s/n/1.2.3+a"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		name, selector, ok := npmCoordinate(p)
		if ok && (!npmName.MatchString(name) || len(name) > 214 || (selector != "" && !validNPMTag(selector) && !validNPMVersion(selector))) {
			t.Fatal("invalid coordinate escaped parser")
		}
	})
}
