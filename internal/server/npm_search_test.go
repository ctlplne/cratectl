// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"strings"
	"testing"
)

func TestNPMSearchQueryBounds(t *testing.T) {
	text, from, size, ok := npmSearchQuery("text=%40cratectl%2Flib+main&from=10&size=25&quality=0.65&popularity=0.98&maintenance=0.5")
	if !ok || text != "@cratectl/lib main" || from != 10 || size != 25 {
		t.Fatalf("stock npm search query = %q, %d, %d, %v", text, from, size, ok)
	}
	_, from, size, ok = npmSearchQuery("text=cratectl")
	if !ok || from != 0 || size != 20 {
		t.Fatalf("default search page = %d, %d, %v", from, size, ok)
	}
	for _, query := range []string{
		"size=1", "text=++", "text=%FF", "text=lib%0Afoo", "text=%",
		"text=lib&text=other", "text=lib&size=10&size=20", "text=lib&size=101",
		"text=lib&size=-1", "text=lib&from=10001", "text=lib&from=",
		"text=" + strings.Repeat("x", 257), "text=" + strings.Repeat("x+", 17), strings.Repeat("x", 2049),
	} {
		if _, _, _, ok = npmSearchQuery(query); ok {
			t.Errorf("accepted invalid search query %q", query)
		}
	}
}
