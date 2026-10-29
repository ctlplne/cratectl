// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"regexp"
	"testing"
)

func FuzzLiteralSearchDoesNotTurnInputIntoOperators(f *testing.F) {
	for _, v := range []string{"", "É-package", "[a-z]+.*(?i)", "\\u1234", "Σσς", "Kelvin", "quote'and\"double", "😀"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if (ListRequest{Limit: 1, Query: value}).Validate() != nil {
			return
		}
		pattern := literalSearch(value)
		if len(pattern) > 8*len(value)+2 {
			t.Fatal("literal expansion exceeded its byte bound")
		}
		matcher, e := regexp.Compile("^(?:" + pattern + ")$")
		if e != nil {
			t.Fatal("validated literal made an invalid pattern")
		}
		if !matcher.MatchString(value) {
			t.Fatal("literal does not match itself")
		}
		if matcher.MatchString(value+"\x00") || matcher.MatchString("\x00"+value) {
			t.Fatal("literal input escaped its match boundaries")
		}
	})
}
