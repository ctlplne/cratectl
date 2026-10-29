// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestInventoryOrderedPagesMetadataAndIdentityFences(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, e := New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	for _, payload := range []string{"first bytes", "second bytes", "third bytes"} {
		if _, e = s.Put(ctx, "test-a", strings.NewReader(payload), "", -1); e != nil {
			t.Fatal(e)
		}
	}
	id, e := s.InventoryRoot("test-a")
	if e != nil {
		t.Fatal(e)
	}
	testNames := []string{"upload-z", "upload-a", "upload-b"}
	if os.PathSeparator == '/' {
		testNames = append(testNames, "upload-\\odd")
	}
	for _, name := range testNames {
		if e = os.WriteFile(filepath.Join(root, "test-a", "staged", name), []byte("retained"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	names := []string{}
	after := ""
	for n := 0; n < 10; n++ {
		page, e := s.ListInventoryPage(ctx, "test-a", id, "staged", "", after, 1, 10)
		if e != nil {
			t.Fatal(e)
		}
		if len(page.Entries) != 1 {
			t.Fatal("bad bounded page", page)
		}
		item := page.Entries[0]
		names = append(names, item.Name)
		after = item.NameB64
		if !page.More {
			break
		}
	}
	expected := append([]string(nil), names...)
	sort.Strings(expected)
	if len(names) != len(testNames) || !equalNames(names, expected) {
		t.Fatal("noncanonical walk", names)
	}
	if _, e = s.ListInventoryPage(ctx, "test-a", id, "staged", "", "", 1, 2); !errors.Is(e, ErrInventoryBudget) {
		t.Fatal("directory budget ignored", e)
	}
	payload := []byte("first bytes")
	digest := crypt.Digest(payload)
	page, e := s.ListInventoryPage(ctx, "test-a", id, "cas", digest[:2], "", 100, 100)
	if e != nil {
		t.Fatal(e)
	}
	var entry InventoryEntry
	for _, item := range page.Entries {
		if item.Digest == digest {
			entry = item
		}
	}
	status, e := s.CheckInventoryObject(ctx, "test-a", id, entry, 1<<20, 0)
	if e != nil || status != "verified" {
		t.Fatal(status, e)
	}
	if e = os.WriteFile(filepath.Join(root, "test-a", "sha256", digest[:2], digest), []byte("other bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	if status, e = s.CheckInventoryObject(ctx, "test-a", id, entry, 1<<20, 0); e != nil || status != "changed" {
		t.Fatal("changed identity/metadata accepted", status, e)
	}
	if e = os.Rename(filepath.Join(root, "test-a"), filepath.Join(root, "old-test-a")); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "test-a"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ListInventoryPage(ctx, "test-a", id, "root", "", "", 10, 100); !errors.Is(e, ErrStorageChanged) {
		t.Fatal("replacement root merged into run", e)
	}
}
func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}

func FuzzInventoryFilenameCursor(f *testing.F) {
	for _, name := range []string{"", "upload-a", "upload-\\odd", "a\x00b", "../escape", "é", "\xffraw"} {
		f.Add(base64.RawURLEncoding.EncodeToString([]byte(name)))
	}
	f.Add("invalid===")
	f.Fuzz(func(t *testing.T, encoded string) {
		name, e := inventoryName(encoded)
		if e == nil && (len(name) > 255 || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." || base64.RawURLEncoding.EncodeToString([]byte(name)) != encoded) {
			t.Fatalf("unsafe filename cursor %q", encoded)
		}
	})
}
