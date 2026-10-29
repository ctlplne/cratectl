// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"fmt"
	"strings"
	"testing"
)

func FuzzJobID(f *testing.F) {
	f.Add("1:event")
	f.Add("23:integrity-" + strings.Repeat("a", 64))
	f.Add("42:reconcile-" + strings.Repeat("b", 64))
	f.Add("01:event")
	f.Add("-1:event")
	f.Add("1:unknown")
	f.Fuzz(func(t *testing.T, raw string) {
		n, task, e := ParseJobID(raw)
		if e == nil && (len(raw) > 96 || n < 1 || fmt.Sprintf("%d:%s", n, task) != raw) {
			t.Fatal("accepted an ambiguous job selector")
		}
	})
}
