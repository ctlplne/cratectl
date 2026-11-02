// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"errors"
	"strings"
	"testing"
)

func TestVersionIdentityCollisions(t *testing.T) {
	groups := map[string][]string{
		"1.0.0":          {"1", "1.0", "1.0.0", "1.0.0.0", "01.00.000.0000", "1.0.0+build.123", " 1 . 0 . 0 ", "\t1.0.0\r\n"},
		"1.1.1":          {"1.01.1", "1.1.01.0", "1.1.1+different-source"},
		"1.0.0.1":        {"1.00.0.1", "1.0.0.01+build"},
		"1.0.0-alpha.1":  {"1-alpha.1", "1.0.0-Alpha.1", "1.0.0.0-ALPHA.1+ignored"},
		"0.0.0-0a.0":     {"0-0a.0", "000.0.0-0A.0+000"},
		"2147483647.0.0": {"2147483647", "2147483647.00.0.0"},
	}
	for expected, values := range groups {
		for _, value := range values {
			t.Run(value, func(t *testing.T) {
				actual, err := VersionKey(value)
				if err != nil || actual != expected {
					t.Fatalf("identity %q, %v; want %q", actual, err, expected)
				}
			})
		}
	}
}

func TestVersionRejectsAmbiguousOrInvalidKeys(t *testing.T) {
	for _, value := range []string{"", " ", "v1.0", "1.", ".1", "1..0", "1.2.3.4.5", "-1", "+1", "2147483648", "1.2147483648", "1-", "1+", "1-a..b", "1-a.01", "1-00", "1+build..value", "1+build+another", "1-α", "１.0", "1.0/../../x", "1\x00", "1-a b", "1-foo_bar", "1+foo/bar", "[1.0,2.0)", "1.*", "1 2", "1.\n", strings.Repeat("0", MaxVersionBytes) + "1"} {
		t.Run(value, func(t *testing.T) {
			key, err := VersionKey(value)
			if !errors.Is(err, ErrVersion) || key != "" {
				t.Fatalf("invalid input produced identity %q, %v", key, err)
			}
		})
	}
}

func TestDistinctNativeVersionIdentitiesStayDistinct(t *testing.T) {
	values := []string{"1.0.0", "1.0.0.1", "1.0.1", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha-1", "1.0.0-alpha.2", "1.0.0-0a", "1.0.0-a0"}
	seen := map[string]bool{}
	for _, value := range values {
		key, err := VersionKey(value)
		if err != nil || seen[key] {
			t.Fatalf("distinct coordinate collision %q: %v", key, err)
		}
		seen[key] = true
	}
}

func TestVersionBudgetIncludesCanonicalPadding(t *testing.T) {
	key, err := VersionKey("1-" + strings.Repeat("a", MaxVersionBytes-6))
	if err != nil || len(key) != MaxVersionBytes {
		t.Fatal("maximum canonical identity rejected", err)
	}
	if again, err := VersionKey(key); err != nil || again != key {
		t.Fatal("maximum canonical identity cannot be read back", err)
	}
	if key, err := VersionKey("1-" + strings.Repeat("a", MaxVersionBytes-5)); err != ErrVersion || key != "" {
		t.Fatal("padding exceeded canonical output budget", err)
	}
}

func FuzzVersionIdentity(f *testing.F) {
	for _, value := range []string{"1", "1.00.0.0", "1.0.0-Alpha.1+build.23", "1.0.0.1", "1-a.01", "1+", "2147483648", "../private", "\x00"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		key, err := VersionKey(value)
		if err != nil {
			if key != "" || !errors.Is(err, ErrVersion) {
				t.Fatal("invalid version yielded partial identity")
			}
			return
		}
		if len(key) > MaxVersionBytes+4 || strings.ContainsAny(key, "/\\+\r\n\x00") || key != strings.ToLower(key) {
			t.Fatal("unsafe normalized identity")
		}
		again, err := VersionKey(key)
		if err != nil || again != key {
			t.Fatal("version normalization is not idempotent")
		}
		withMetadata, err := VersionKey(key + "+cratectl.synthetic")
		if len(key)+len("+cratectl.synthetic") <= MaxVersionBytes && (err != nil || withMetadata != key) {
			t.Fatal("build metadata changed immutable package identity")
		}
	})
}
