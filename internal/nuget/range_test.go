// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"errors"
	"strings"
	"testing"
)

func TestVersionRangeIntervalsAndAliases(t *testing.T) {
	for _, tc := range []struct {
		raw, normalized, inside, outside string
	}{
		{"1", "[1.0.0, )", "2", "0.9"},
		{"[1]", "[1.0.0, 1.0.0]", "1.0+build", "1.0.0.1"},
		{"(,2]", "(, 2.0.0]", "2", "2.0.0.1"},
		{"[1,2)", "[1.0.0, 2.0.0)", "1.9", "2"},
		{"(1,2]", "(1.0.0, 2.0.0]", "2", "1.0+ignored"},
		{"[1.0-ALPHA+source,1.0]", "[1.0.0-alpha, 1.0.0]", "1.0-alpha.1", "1.1"},
		{"[1.2.3.4,1.2.3.5)", "[1.2.3.4, 1.2.3.5)", "1.2.3.4", "1.2.3.5"},
		{"[1.0--0,1.0-0]", "[1.0.0--0, 1.0.0-0]", "1.0--00", "1.0-1"},
	} {
		r, e := ParseVersionRange(tc.raw)
		if e != nil || r.Info().Normalized != tc.normalized {
			t.Fatal("range normalization", tc.raw, r.Info(), e)
		}
		if yes, e := r.Satisfies(tc.inside); e != nil || !yes {
			t.Fatal("admitted dependency rejected", tc.raw, tc.inside, e)
		}
		if yes, e := r.Satisfies(tc.outside); e != nil || yes {
			t.Fatal("dependency escaped range", tc.raw, tc.outside, e)
		}
	}
	for _, input := range []string{"", "[]", "(,)", "(1)", "[1,1)", "(1,1]", "[2,1]", "[1,*]", "[1,2,3]", "[v1]", "[2147483648]", "1.*+build", "**", "1.*.0", strings.Repeat(" ", MaxVersionRangeBytes+1)} {
		r, e := ParseVersionRange(input)
		if !errors.Is(e, ErrVersionRange) || r.valid || r.Info() != (VersionRangeInfo{}) {
			t.Fatal("invalid range returned partial state", input, e)
		}
	}
	for _, input := range []string{"(, )", "[ ]", "[, ]"} {
		r, e := ParseVersionRange(input)
		if e != nil || r.Info().Normalized != "(, )" {
			t.Fatal("explicit whitespace-bound all range", input, r.Info(), e)
		}
	}
	empty, e := ParseVersionRange("(1,1)")
	if yes, err := empty.Satisfies("1"); e != nil || err != nil || yes {
		t.Fatal("empty interval widened", e, err)
	}
	if yes, e := (VersionRange{}).Satisfies("1"); !errors.Is(e, ErrVersionRange) || yes {
		t.Fatal("unparsed zero value admitted a dependency")
	}
}

func TestVersionRangeFloatingPreferenceIsSeparateFromMembership(t *testing.T) {
	for _, tc := range []struct {
		raw, normalized, minimum, preferred, other string
	}{
		{"*", "[*, )", "0.0.0", "5", "5-alpha"},
		{"1.*", "[1.*, )", "1.0.0", "1.9", "2"},
		{"1.2.*", "[1.2.*, )", "1.2.0", "1.2.9", "1.3"},
		{"1.2.3.*", "[1.2.3.*, )", "1.2.3", "1.2.3.9", "1.2.4"},
		{"1.2.3-rc.*", "[1.2.3-rc.*, )", "1.2.3-rc.0", "1.2.3-rc.10", "1.2.3-other"},
		{"1.2.3-*", "[1.2.3-*, )", "1.2.3-0", "1.2.3-alpha", "1.2.4-alpha"},
		{"1.*-RC*", "[1.*-rc*, )", "1.0.0-rc", "1.9-RC10", "2.0-rc"},
		{"1.2.*-*", "[1.2.*-*, )", "1.2.0-0", "1.2.9-beta", "1.3-beta"},
		{"1.2.3.*-*", "[1.2.3.*-*, )", "1.2.3-0", "1.2.3.4-beta", "1.2.4-beta"},
		{"1.0.0-alpha-*", "[1.0.0-alpha-*, )", "1.0.0-alpha-", "1.0.0-alpha-next", "1.0.0-beta"},
	} {
		r, e := ParseVersionRange(tc.raw)
		if e != nil || r.Info().Normalized != tc.normalized || r.Info().Min != tc.minimum || !r.Info().Floating {
			t.Fatal("floating metadata changed", tc.raw, r.Info(), e)
		}
		if yes, e := r.FloatSatisfies(tc.preferred); e != nil || !yes {
			t.Fatal("preferred floating version rejected", tc.raw, e)
		}
		if yes, e := r.FloatSatisfies(tc.other); e != nil || yes {
			t.Fatal("floating prefix widened", tc.raw, e)
		}
	}
	r, _ := ParseVersionRange("1.*")
	if member, _ := r.Satisfies("2"); !member {
		t.Fatal("floating preference became an implicit interval ceiling")
	}
	r, _ = ParseVersionRange("[1.2.*-*,2)")
	if yes, _ := r.FloatSatisfies("1.2.0"); !yes {
		t.Fatal("stable version excluded from prerelease floating preference")
	}
	r, _ = ParseVersionRange("*-*")
	if yes, e := r.FloatSatisfies("2147483647.0.0-alpha"); e != nil || !yes {
		t.Fatal("absolute latest floating preference", e)
	}
	// Preserve the SDK's admitted noncanonical wildcard behavior. Reformatting
	// such a float is not a lossless replacement for its parsed minimum.
	r, e := ParseVersionRange("1.2*")
	if e != nil || r.Info().Min != "1.20.0" || r.Info().FloatString != "1.*" {
		t.Fatal("noncanonical floating minimum lost", r.Info(), e)
	}
	r, e = ParseVersionRange("1*")
	if e != nil || r.Info().Floating || r.Info().Min != "10.0.0" || r.Info().FloatString != "10.0.0" {
		t.Fatal("nonfloating wildcard minimum changed", r.Info(), e)
	}
}

func FuzzNuGetVersionRange(f *testing.F) {
	for _, seed := range []string{"[1,2)", "*", "1.2.*-*", "(, )", "(1,1)", "1.0.0-alpha-*", "1.2*", "[1.0--0,1.0-0]"} {
		f.Add(seed, "1.2.3-alpha.1")
	}
	f.Fuzz(func(t *testing.T, input, candidate string) {
		r, e := ParseVersionRange(input)
		if e != nil {
			if r.valid || r.Info() != (VersionRangeInfo{}) {
				t.Fatal("failed range parse produced partial data")
			}
			return
		}
		info := r.Info()
		if len(info.Normalized) > MaxVersionRangeBytes || len(info.Min) > MaxVersionBytes || len(info.Max) > MaxVersionBytes {
			t.Fatal("range escaped byte bounds")
		}
		yes, e := r.Satisfies(candidate)
		_, floatError := r.FloatSatisfies(candidate)
		_, versionError := VersionKey(candidate)
		if (e != nil) != (versionError != nil) || (floatError != nil) != (versionError != nil) {
			t.Fatal("candidate validity disagrees")
		}
		if yes && info.Min != "" {
			order, _ := CompareVersions(candidate, info.Min)
			if order < 0 || order == 0 && !info.IncludeMin {
				t.Fatal("range admitted below its minimum")
			}
		}
		if yes && info.Max != "" {
			order, _ := CompareVersions(candidate, info.Max)
			if order > 0 || order == 0 && !info.IncludeMax {
				t.Fatal("range admitted above its maximum")
			}
		}
	})
}
