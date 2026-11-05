// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func TestLatestVersionDoesNotDependOnIndexOrder(t *testing.T) {
	for _, test := range []struct {
		versions []string
		want     string
	}{
		{nil, ""},
		{[]string{"v1.10.0", "v1.2.0", "v1.20.0-beta"}, "v1.10.0"},
		{[]string{"v1.20.0-beta", "v1.2.0-beta"}, "v1.20.0-beta"},
		{[]string{"v0.0.0-20261104010203-0123456789ab", "v1.0.1-0.20251004010203-0123456789ab"}, "v0.0.0-20261104010203-0123456789ab"},
		{[]string{"bad", "v1.0.0"}, "v1.0.0"},
	} {
		if got := LatestVersion(test.versions); got != test.want {
			t.Fatal("latest depended on order or ignored native preference", got, test.want)
		}
	}
}

func TestUpstreamVersionListIsCompleteCanonicalAndSemanticallyOrdered(t *testing.T) {
	for _, tc := range []struct {
		mod, body string
		want      []string
	}{
		{"go.cratectl.invalid/Owned/app", "", []string{}},
		{"go.cratectl.invalid/Owned/app", "v1.10.0\r\nv1.2.0\nv1.10.0-beta\n\n", []string{"v1.2.0", "v1.10.0-beta", "v1.10.0"}},
		{"go.cratectl.invalid/Owned/app/v2", "v2.0.0-Alpha\nv2.0.0\n", []string{"v2.0.0-Alpha", "v2.0.0"}},
	} {
		data := []byte(tc.body)
		got, e := ParseVersionList(data, tc.mod, 3, 1024)
		if e != nil || !reflect.DeepEqual(got, tc.want) || string(data) != tc.body {
			t.Fatal("version advertisement changed or rejected", got, e)
		}
	}
	if got, e := ParseVersionList([]byte("v1.0.0"), testCoordinate.Module, 1, 6); e != nil || len(got) != 1 {
		t.Fatal("exact entry/byte budget rejected", got, e)
	}
}

func TestUpstreamVersionListNeverReturnsPartialOrAmbiguousAdvertisements(t *testing.T) {
	for _, body := range []string{
		"v1.0.0\nv1.0.0\n", "v1.0.0\nv1.1\n", "v1.0.0\nlatest\n",
		"v1.0.0\n v1.1.0\n", "v1.0.0\nv1.1.0 \n", "v1.0.0\nv1.1.0\t\n",
		"v1.0.0\nv1.1.0\x00\n", "v1.0.0\nv2.0.0\n", "v1.0.0\nv1.1.0+alias\n",
		"v1.0.0\nv1.0.1-0.20260102030405-0123456789ab\n", "v1.0.0\nv1.0.1-0.20261302030405-0123456789ab\n",
		"v1.0.0\n" + string([]byte{255}), "v1.0.0\n" + strings.Repeat("v", MaxVersion+1),
	} {
		if got, e := ParseVersionList([]byte(body), testCoordinate.Module, 3, 1024); !errors.Is(e, ErrModule) || got != nil {
			t.Fatal("partial/ambiguous advertisement accepted", got, e)
		}
	}
	for _, tc := range []struct {
		mod     string
		maximum int
		budget  int64
	}{
		{testCoordinate.Module, 1, 1024}, {testCoordinate.Module, 3, 6},
		{testCoordinate.Module, 0, 1024}, {testCoordinate.Module, 10001, 1024},
		{testCoordinate.Module, 3, 0}, {testCoordinate.Module, 3, (64 << 20) + 1},
		{"go.cratectl.invalid/../app", 3, 1024}, {strings.Repeat("x", MaxModulePath+1), 3, 1024},
	} {
		if got, e := ParseVersionList([]byte("v1.0.0\nv1.1.0\n"), tc.mod, tc.maximum, tc.budget); !errors.Is(e, ErrModule) || got != nil {
			t.Fatal("unsafe advertisement budget/module accepted or valid prefix returned", got, e)
		}
	}
}

func TestUpstreamVersionListBoundsMemoryForManyEmptyPhysicalLines(t *testing.T) {
	data := bytes.Repeat([]byte{'\n'}, 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, e := ParseVersionList(data, testCoordinate.Module, 1, int64(len(data)))
	runtime.ReadMemStats(&after)
	if e != nil || len(got) != 0 {
		t.Fatal("empty native advertisement changed", e)
	}
	// The input is already owned. One million empty lines must not allocate a
	// million-element slice before the logical version budget can be applied.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 512<<10 {
		t.Fatal("physical-line count amplified parser memory", allocated)
	}
}

func FuzzUpstreamVersionList(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("v1.0.0\nv1.1.0\n"), []byte("v1.0.0\nv1.0.0\n"), []byte("v1.0.0\nlatest\n")} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		got, e := ParseVersionList(data, testCoordinate.Module, 16, 4096)
		if !bytes.Equal(before, data) {
			t.Fatal("input bytes changed")
		}
		if e != nil {
			if got != nil {
				t.Fatal("partial list returned")
			}
			return
		}
		if len(data) > 4096 || len(got) > 16 {
			t.Fatal("resource budget escaped")
		}
		seen := map[string]bool{}
		for n, version := range got {
			if _, e := Canonical(testCoordinate.Module, version); e != nil || seen[version] || module.IsPseudoVersion(version) || n > 0 && semver.Compare(got[n-1], version) > 0 {
				t.Fatal("advertisement identity/order invariant", version, e)
			}
			seen[version] = true
		}
	})
}
