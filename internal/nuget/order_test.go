// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type cancelOrderAfterChecks struct {
	context.Context
	cancel context.CancelFunc
	checks int
	limit  int
}

func (c *cancelOrderAfterChecks) Err() error {
	c.checks++
	if c.checks == c.limit {
		c.cancel()
	}
	return c.Context.Err()
}

func TestVersionOrderingUsesNumericCoreAndSDKReleaseProfile(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		order       int
	}{
		{"2.0", "10.0", -1}, {"01.0.0.0+first", "1+second", 0},
		{"1.0.0.1", "1.0.0", 1}, {"2147483647.0", "2.0", 1},
		{"1.0.0-alpha", "1.0.0", -1}, {"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0-alpha10", "1.0.0-alpha2", -1}, {"1.0.0-ALPHA", "1.0.0-alpha", 0},
		{"1.0.0-alpha", "1.0.0-alpha.0", -1}, {"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0--1", "1.0.0-0", -1}, {"1.0.0--0", "1.0.0-0", 0},
		{"1.0.0--01", "1.0.0--1", 0}, {"1.0.0--2147483648", "1.0.0-0", -1},
		{"1.0.0--2147483649", "1.0.0-0", 1},
		{"1.0.0-2147483648", "1.0.0-10000000000", 1},
	} {
		got, e := CompareVersions(tc.left, tc.right)
		if e != nil || got != tc.order {
			t.Errorf("%q versus %q: %d, %v; want %d", tc.left, tc.right, got, e, tc.order)
		}
		back, e := CompareVersions(tc.right, tc.left)
		if e != nil || back != -tc.order {
			t.Fatal("comparison is not antisymmetric", tc.left, tc.right, back, e)
		}
	}
	left, _ := VersionKey("1.0.0--0")
	right, _ := VersionKey("1.0.0-0")
	if left == right {
		t.Fatal("an ordering tie merged distinct coordinate keys")
	}
}

func TestVersionSortIsStableBoundedAndDoesNotPublishPartialResults(t *testing.T) {
	input := []string{"10.0.0", "1.0.0-0", "2.0.0", "1.0.0--0", "1.0.0-rc.10", "1.0.0-rc.2", "1.0.0"}
	original := append([]string(nil), input...)
	actual, e := SortVersionKeys(context.Background(), input)
	want := []string{"1.0.0-0", "1.0.0--0", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0", "2.0.0", "10.0.0"}
	if e != nil || !reflect.DeepEqual(actual, want) || !reflect.DeepEqual(input, original) {
		t.Fatal("ordering, stable ties or input changed", actual, input, e)
	}
	for _, invalid := range [][]string{{"2.0.0", "invalid", "1.0.0"}, {"1.0.0", "1.0"}, make([]string, MaxOrderedVersions+1), {strings.Repeat("1", MaxVersionBytes+1)}} {
		if result, e := SortVersionKeys(context.Background(), invalid); e == nil || result != nil {
			t.Fatal("invalid sort returned partial data", len(result), e)
		}
	}
	large := make([]string, MaxOrderedVersionBytes/MaxVersionBytes+1)
	key := "1.0.0-" + strings.Repeat("a", MaxVersionBytes-6)
	for index := range large {
		large[index] = key
	}
	if result, e := SortVersionKeys(context.Background(), large); e == nil || result != nil {
		t.Fatal("aggregate sort byte budget did not fail before allocation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, e := SortVersionKeys(ctx, input); !errors.Is(e, context.Canceled) || result != nil {
		t.Fatal("cancelled sort returned data", result, e)
	}
	observed := &cancelOrderAfterChecks{Context: context.Background()}
	if _, e := SortVersionKeys(observed, input); e != nil {
		t.Fatal(e)
	}
	for at := 1; at <= observed.checks; at++ {
		parent, stop := context.WithCancel(context.Background())
		controlled := &cancelOrderAfterChecks{Context: parent, cancel: stop, limit: at}
		result, e := SortVersionKeys(controlled, input)
		stop()
		if !errors.Is(e, context.Canceled) || result != nil || !reflect.DeepEqual(input, original) {
			t.Fatal("cancellation during merge exposed data or changed input", at, result, e)
		}
	}
	for _, invalid := range []string{"", "v1", "1.0.0-01", "2147483648", strings.Repeat("1", MaxVersionBytes+1)} {
		if order, e := CompareVersions("1.0", invalid); e == nil || order != 0 {
			t.Fatal("invalid comparison returned a partial order", order, e)
		}
	}
}

func FuzzVersionOrdering(f *testing.F) {
	for _, seeds := range [][3]string{{"1.0", "2.0", "10.0"}, {"1.0.0-rc.2", "1.0.0-rc.10", "1.0.0"}, {"1.0.0--1", "1.0.0-0", "1.0.0-alpha"}, {"1.0.0-2147483648", "1.0.0-10000000000", "1.0.0-alpha"}} {
		f.Add(seeds[0], seeds[1], seeds[2])
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab, e := CompareVersions(a, b)
		if e != nil {
			if ab != 0 {
				t.Fatal("invalid comparison produced an order")
			}
			return
		}
		ba, e := CompareVersions(b, a)
		if e != nil || ab != -ba {
			t.Fatal("antisymmetry")
		}
		bc, e := CompareVersions(b, c)
		if e != nil {
			return
		}
		ac, e := CompareVersions(a, c)
		if e != nil || ab <= 0 && bc <= 0 && ac > 0 || ab >= 0 && bc >= 0 && ac < 0 {
			t.Fatal("transitivity")
		}
		keys := make([]string, 0, 3)
		counts := map[string]int{}
		for _, raw := range []string{c, a, b} {
			key, e := VersionKey(raw)
			if e != nil {
				t.Fatal("comparable version has no key", e)
			}
			keys = append(keys, key)
			counts[key]++
		}
		ordered, e := SortVersionKeys(context.Background(), keys)
		if e != nil || len(ordered) != len(keys) {
			t.Fatal("valid canonical sort failed", e)
		}
		for index, key := range ordered {
			counts[key]--
			if index > 0 {
				order, e := CompareVersions(ordered[index-1], key)
				if e != nil || order > 0 {
					t.Fatal("merge result is not ascending")
				}
			}
		}
		for _, count := range counts {
			if count != 0 {
				t.Fatal("merge lost or invented a coordinate key")
			}
		}
	})
}
