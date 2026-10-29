//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestIntegrityRejectsSpecialFileWithoutBlocking(t *testing.T) {
	s, e := New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	digest := crypt.Digest([]byte("owned fifo fixture"))
	path, e := s.path("test-a", digest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Mkfifo(path, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan string, 1)
	go func() { status, _ := s.CheckStored(ctx, "test-a", digest, 18, 1<<20, 0); done <- status }()
	select {
	case status := <-done:
		if status != "io_error" {
			t.Fatal("unsupported special file was not rejected", status)
		}
	case <-time.After(300 * time.Millisecond):
		// Release the old blocking open so a retained failure never leaves a goroutine.
		release, e := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if e != nil {
			t.Fatal(e)
		}
		release.Close()
		<-done
		t.Fatal("integrity inspection blocked opening a special file beyond its context deadline")
	}
}
