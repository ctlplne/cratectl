// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestWriteNewPrivateKeepsExactBytesAndRefusesConcurrentOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cratectl-client-output")
	start := make(chan struct{})
	type outcome struct {
		raw []byte
		err error
	}
	results := make(chan outcome, 2)
	for _, raw := range [][]byte{[]byte("owned first"), []byte("owned second")} {
		go func() {
			<-start
			results <- outcome{raw: raw, err: WriteNewPrivate(path, raw)}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if (first.err == nil) == (second.err == nil) {
		t.Fatal("exclusive create must admit exactly one writer")
	}
	winner := first.raw
	if first.err != nil {
		winner = second.raw
	}
	if err := WriteNewPrivate(path, []byte("owned later attempt")); err == nil {
		t.Fatal("existing output was overwritten")
	}
	got, err := ReadBytes(path, 128, true)
	if err != nil || !bytes.Equal(got, winner) {
		t.Fatal("private output changed or failed its permissions check", err)
	}
}
