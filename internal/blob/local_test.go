// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
)

func TestPublicationAndIntegrity(t *testing.T) {
	b, e := New(t.TempDir(), 8)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, e = b.Put(ctx, "a", bytes.NewBufferString("123456789"), "", -1); !errors.Is(e, ErrLimit) {
		t.Fatalf("limit: %v", e)
	}
	if _, e = b.Put(ctx, "a", bytes.NewBufferString("hello"), "", 6); e == nil {
		t.Fatal("accepted wrong length")
	}
	if _, e = b.Put(ctx, "a", bytes.NewBufferString("hello"), "0000", 5); e == nil {
		t.Fatal("accepted wrong digest")
	}
	a, e := b.Put(ctx, "a", bytes.NewBufferString("hello"), "", 5)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Open("b", a.Digest); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("cross-tenant object: %v", e)
	}
	var wg sync.WaitGroup
	for n := 0; n < 10; n++ {
		wg.Go(func() {
			if _, e := b.Put(ctx, "a", bytes.NewBufferString("hello"), a.Digest, 5); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	f, e := b.Open("a", a.Digest)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(f)
	f.Close()
	if e != nil || string(got) != "hello" {
		t.Fatal("wrong bytes")
	}
	p, _ := b.path("a", a.Digest)
	if e = os.WriteFile(p, []byte("wrong"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Put(ctx, "a", bytes.NewBufferString("hello"), a.Digest, 5); e == nil {
		t.Fatal("reused corrupt object")
	}
}
func TestCancellationAndNamespace(t *testing.T) {
	b, _ := New(t.TempDir(), 100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := b.Put(ctx, "a", bytes.NewBufferString("x"), "", 1); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, n := range []string{"../a", "A", "a/b", "", "a\\b"} {
		if _, e := b.Put(context.Background(), n, bytes.NewBufferString("x"), "", 1); e == nil {
			t.Fatalf("accepted %q", n)
		}
	}
}
