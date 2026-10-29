// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStoredIntegrityIsBoundedAndCancellable(t *testing.T) {
	s, e := New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	data := bytes.Repeat([]byte("x"), 128<<10)
	object, e := s.Put(ctx, "tenant", bytes.NewReader(data), "", int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	if status, e := s.CheckStored(ctx, "tenant", object.Digest, object.Size, 1<<20, 0); e != nil || status != "verified" {
		t.Fatal(status, e)
	}
	if status, _ := s.CheckStored(ctx, "tenant", object.Digest, object.Size, 1, 0); status != "limit" {
		t.Fatal("task byte ceiling ignored")
	}
	if status, _ := s.CheckStored(ctx, "tenant", strings.Repeat("f", 64), object.Size, 1<<20, 0); status != "missing" {
		t.Fatal("missing object reported healthy")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if status, e := s.CheckStored(bounded, "tenant", object.Digest, object.Size, 1<<20, 1); e == nil || status != "timeout" || time.Since(start) > 2*time.Second {
		t.Fatal("paced integrity check ignored cancellation", status, e)
	}
	path, e := s.path("tenant", object.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, bytes.Repeat([]byte("y"), len(data)), 0600); e != nil {
		t.Fatal(e)
	}
	if status, _ := s.CheckStored(ctx, "tenant", object.Digest, object.Size, 1<<20, 0); status != "corrupt" {
		t.Fatal("same-length corruption reported healthy")
	}
}
