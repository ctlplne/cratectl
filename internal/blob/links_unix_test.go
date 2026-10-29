//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicationRejectsTenantNamespaceSymlink(t *testing.T) {
	root := t.TempDir()
	s, e := New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "test-b"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("test-b", filepath.Join(root, "test-a")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Put(context.Background(), "test-a", strings.NewReader("must not cross tenant namespace"), "", -1); !errors.Is(e, ErrUnsupported) {
		t.Fatal("publication followed a tenant namespace symlink", e)
	}
	entries, e := os.ReadDir(filepath.Join(root, "test-b"))
	if e != nil || len(entries) != 0 {
		t.Fatal("other tenant bytes were modified", len(entries), e)
	}
}

func TestInventoryDoesNotFollowObjectOrDirectorySymlinks(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, e := New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.Put(ctx, "test-a", strings.NewReader("a"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Put(ctx, "test-b", strings.NewReader("other tenant"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(root, "test-a", "sha256", a.Digest[:2], a.Digest)); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(root, "test-b", "sha256", b.Digest[:2], b.Digest), filepath.Join(root, "test-a", "sha256", a.Digest[:2], a.Digest)); e != nil {
		t.Fatal(e)
	}
	id, e := s.InventoryRoot("test-a")
	if e != nil {
		t.Fatal(e)
	}
	page, e := s.ListInventoryPage(ctx, "test-a", id, "cas", a.Digest[:2], "", 100, 100)
	if e != nil || len(page.Entries) != 1 || page.Entries[0].Type != "symlink" || page.Entries[0].Expected {
		t.Fatal(page, e)
	}
	if _, e = s.Open("test-a", a.Digest); !errors.Is(e, ErrUnsupported) {
		t.Fatal("object link followed", e)
	}
	if e = os.Symlink(filepath.Join(root, "test-b", "sha256"), filepath.Join(root, "test-a", "sha256", "ee")); e != nil {
		t.Fatal(e)
	}
	page, e = s.ListInventoryPage(ctx, "test-a", id, "cas", "ee", "", 100, 100)
	if e != nil || !page.Unsupported || len(page.Entries) != 0 {
		t.Fatal("directory link traversed", page, e)
	}
}
