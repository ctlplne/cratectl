// SPDX-License-Identifier: BUSL-1.1
package server

import "testing"

func FuzzUploadContentRange(f *testing.F) {
	for _, seed := range []string{"", "0-5", "bytes 0-5", "-1-2", "01-2", "0-9223372036854775807", "bytes 2-1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		start, length, e := uploadRange(s)
		if e == nil && s != "" && (start < 0 || length < 1 || start+length > 1<<62) {
			t.Fatalf("unsafe upload range %q: %d %d", s, start, length)
		}
	})
}
