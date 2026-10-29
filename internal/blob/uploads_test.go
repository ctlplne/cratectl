// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestImmutableUploadPartsAndLegacyPrefix(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, e := New(root, 16)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.StageUpload(ctx, "test-a", 0, strings.NewReader("first"), 5)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.StageUpload(ctx, "test-a", 5, strings.NewReader("second"), 6)
	if e != nil {
		t.Fatal(e)
	}
	obj, e := s.AssembleUpload(ctx, "test-a", []Object{a, b}, crypt.Digest([]byte("firstsecond")))
	if e != nil || obj.Size != 11 {
		t.Fatal(obj, e)
	}
	if _, e = s.StageUpload(ctx, "test-a", 15, strings.NewReader("too long"), -1); !errors.Is(e, ErrLimit) {
		t.Fatal("aggregate limit bypassed", e)
	}
	if _, e = s.StageUpload(ctx, "test-a", 0, strings.NewReader("short"), 7); !errors.Is(e, ErrLength) {
		t.Fatal("length mismatch", e)
	}
	// Each part is checked, even if the caller supplies the digest of corrupt bytes.
	path, e := s.path("test-a", a.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("wrong"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.AssembleUpload(ctx, "test-a", []Object{a, b}, crypt.Digest([]byte("wrongsecond"))); !errors.Is(e, ErrIntegrity) {
		t.Fatal("corrupt part admitted", e)
	}
	id := strings.Repeat("a", 43)
	dir := filepath.Join(root, "test-a", "uploads")
	if e = os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	legacy := filepath.Join(dir, id)
	if e = os.WriteFile(legacy, []byte("acknowledged-unacked-tail"), 0600); e != nil {
		t.Fatal(e)
	}
	prefix, e := s.ImportUploadPrefix(ctx, "test-a", id, 12)
	if e != nil {
		t.Fatal(e)
	}
	f, e := s.Open("test-a", prefix.Digest)
	if e != nil {
		t.Fatal(e)
	}
	data, e := io.ReadAll(f)
	f.Close()
	if e != nil || string(data) != "acknowledged" {
		t.Fatal(string(data), e)
	}
	data, e = os.ReadFile(legacy)
	if e != nil || string(data) != "acknowledged-unacked-tail" {
		t.Fatal("legacy file changed", e)
	}
	if _, e = s.ImportUploadPrefix(ctx, "test-a", id, 25); !errors.Is(e, ErrLength) {
		t.Fatal("missing acknowledged bytes admitted", e)
	}
	empty, e := s.AssembleUpload(ctx, "test-a", nil, crypt.Digest(nil))
	if e != nil || empty.Size != 0 {
		t.Fatal("empty blob", empty, e)
	}
}
