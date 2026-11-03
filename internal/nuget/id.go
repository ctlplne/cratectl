// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxIDBytes = 400

var ErrID = errors.New("invalid, unsafe or oversized NuGet package ID")

// IDKey derives the flat-container lookup key from declared package ID text.
// It does not trim whitespace, normalize Unicode, or use a locale. The .NET
// invariant dotted-I rule preserves U+0130 rather than merging it with ASCII i.
func IDKey(value string) (string, error) {
	if len(value) > MaxIDBytes || !utf8.ValidString(value) {
		return "", ErrID
	}
	// This profile is frozen separately from the host Go Unicode tables and
	// from raw Nuspec reading. NuGet's legacy word regex operates on UTF-16 chars.
	units, word := 0, false
	for _, r := range value {
		units++
		if units > 100 {
			return "", ErrID
		}
		if r == '.' || r == '-' {
			if !word {
				return "", ErrID
			}
			word = false
		} else if idProfileWord(r) {
			word = true
		} else {
			return "", ErrID
		}
	}
	if !word {
		return "", ErrID
	}
	key := strings.Map(idProfileLower, value)
	if len(key) > MaxIDBytes {
		return "", ErrID
	}
	return key, nil
}

func idProfileWord(r rune) bool {
	if r < 0 || r > 0xffff {
		return false
	}
	v := uint16(r)
	lo, hi := 0, len(idWordRanges)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if idWordRanges[mid].hi < v {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < len(idWordRanges) && idWordRanges[lo].lo <= v
}

func idProfileLower(r rune) rune {
	if r == 0x0130 || r < 0 || r > 0xffff {
		return r
	}
	v := uint16(r)
	lo, hi := 0, len(idLowerPairs)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if idLowerPairs[mid].from < v {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(idLowerPairs) && idLowerPairs[lo].from == v {
		return rune(idLowerPairs[lo].to)
	}
	return r
}
