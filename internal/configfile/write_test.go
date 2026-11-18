// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"bytes"
	"errors"
	"os"
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

	t.Run("failed owner operation discards its prepared file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cratectl-provision-output")
		commitErr := errors.New("owned operation refused")
		if err := WriteNewPrivateThen(path, []byte("owned prerequisite"), func() error { return commitErr }); !errors.Is(err, commitErr) {
			t.Fatal("prepared output did not report its operation error", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed owner operation retained the prepared credential", err)
		}
		if err := WriteNewPrivate(path, []byte("owned retry")); err != nil {
			t.Fatal("could not retry with the original path", err)
		}
		if err := WriteNewPrivateThen(path, []byte("owned concurrent attempt"), func() error {
			t.Error("existing output still invoked the owner operation")
			return nil
		}); err == nil {
			t.Fatal("existing output did not refuse the owner operation")
		}
	})
}
