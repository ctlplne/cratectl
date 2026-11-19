// SPDX-License-Identifier: BUSL-1.1
package cran

import (
	"cmp"
	"strings"
)

// CompareVersions orders validated R version strings by integer components.
// The two separators are equivalent and trailing zero components are implicit.
// Compare decimal digit strings to avoid overflow on a long valid component.
func CompareVersions(left, right string) int {
	separator := func(r rune) bool { return r == '.' || r == '-' }
	a, b := strings.FieldsFunc(left, separator), strings.FieldsFunc(right, separator)
	for index := range max(len(a), len(b)) {
		var first, second string
		if index < len(a) {
			first = strings.TrimLeft(a[index], "0")
		}
		if index < len(b) {
			second = strings.TrimLeft(b[index], "0")
		}
		if byLength := cmp.Compare(len(first), len(second)); byLength != 0 {
			return byLength
		}
		if byDigits := strings.Compare(first, second); byDigits != 0 {
			return byDigits
		}
	}
	return 0
}
