// SPDX-License-Identifier: BUSL-1.1
package cran

import "testing"

func TestCompareVersionsUsesNumericRComponents(t *testing.T) {
	for _, candidate := range []struct {
		left, right string
		want        int
	}{
		{"1.9.0", "1.10.0", -1},
		{"0.01", "0.1-0", 0},
		{"1.2.4-0", "1.2.3.36", 1},
		{"1.99999999999999999999999999", "1.100000000000000000000000000", -1},
	} {
		if got := CompareVersions(candidate.left, candidate.right); got != candidate.want || CompareVersions(candidate.right, candidate.left) != -candidate.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", candidate.left, candidate.right, got, candidate.want)
		}
	}
}
