// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxIDBytes = 400

var ErrID = errors.New("invalid, unsafe or oversized NuGet package ID")

// IDKey derives the flat-container lookup key from declared package ID text.
// It does not trim whitespace, normalize Unicode, or use a locale. The .NET
// invariant dotted-I rule preserves U+0130 rather than merging it with ASCII i.
func IDKey(value string) (string, error) {
	if len(value) > MaxIDBytes || !utf8.ValidString(value) || !validNuspecID(value) {
		return "", ErrID
	}
	// NuGet's legacy regex validates UTF-16 chars; surrogate code units are
	// outside its word categories. Keep this distinct from raw Nuspec reading.
	if strings.ContainsFunc(value, func(r rune) bool { return r > 0xffff }) {
		return "", ErrID
	}
	key := strings.Map(func(r rune) rune {
		if r == 0x0130 {
			return r
		}
		return unicode.ToLower(r)
	}, value)
	if len(key) > MaxIDBytes {
		return "", ErrID
	}
	return key, nil
}
