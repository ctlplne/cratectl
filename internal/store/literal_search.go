// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"regexp"
	"strings"
	"unicode"
)

// literalSearch expands Unicode simple-fold equivalences explicitly. PostgreSQL
// lower()/ILIKE otherwise depend on the installation's LC_CTYPE. Only literals
// and explicit character classes are emitted; user regex operators stay quoted.
func literalSearch(query string) string {
	var pattern strings.Builder
	for _, r := range query {
		next := unicode.SimpleFold(r)
		if next == r {
			pattern.WriteString(regexp.QuoteMeta(string(r)))
			continue
		}
		pattern.WriteByte('[')
		pattern.WriteRune(r)
		for next != r {
			pattern.WriteRune(next)
			next = unicode.SimpleFold(next)
		}
		pattern.WriteByte(']')
	}
	return pattern.String()
}
