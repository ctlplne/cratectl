// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestRepairExactBytesRetainsCorruptionAndLeavesHealthyInode(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, e := New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	data := []byte("independently retained exact artifact bytes")
	digest := crypt.Digest(data)
	object, e := s.Put(ctx, "tenant-a", bytes.NewReader(data), digest, int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "tenant-a", "sha256", digest[:2], digest)
	corrupt := bytes.Repeat([]byte("X"), len(data))
	if e = os.WriteFile(path, corrupt, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Put(ctx, "tenant-a", bytes.NewReader(data), digest, object.Size); !errors.Is(e, ErrIntegrity) {
		t.Fatal("ordinary publication overwrote corrupt bytes", e)
	}
	rootID, e := s.InventoryRoot("tenant-a")
	if e != nil {
		t.Fatal(e)
	}
	source, e := s.StageRepair(ctx, "tenant-a", rootID, digest, object.Size, bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := s.PrepareRepair(ctx, "tenant-a", source, 1<<20, 0)
	if e != nil {
		t.Fatal(e)
	}
	result, e := prepared.Install(ctx)
	prepared.Close()
	if e != nil || result.Before != "corrupt" || !result.Installed || !result.RetainedPrevious {
		t.Fatal(result, e)
	}
	verified, e := s.OpenVerified(ctx, "tenant-a", digest, object.Size)
	if e != nil {
		t.Fatal(e)
	}
	verified.Close()
	found := false
	entries, e := os.ReadDir(filepath.Join(root, "tenant-a", "staged"))
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		body, e := os.ReadFile(filepath.Join(root, "tenant-a", "staged", entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Equal(body, corrupt) {
			found = true
		}
	}
	if !found {
		t.Fatal("original corrupt inode was not retained")
	}
	before, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	prepared, e = s.PrepareRepair(ctx, "tenant-a", source, 1<<20, 0)
	if e != nil {
		t.Fatal(e)
	}
	result, e = prepared.Install(ctx)
	prepared.Close()
	if e != nil || result.Installed || result.Before != "verified" {
		t.Fatal(result, e)
	}
	after, e := os.Stat(path)
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("healthy target was replaced", e)
	}
}

func TestRepairMissingAndSourceValidationFailClosed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, e := New(root, 100)
	if e != nil {
		t.Fatal(e)
	}
	data := []byte("missing bytes")
	digest := crypt.Digest(data)
	size := int64(len(data))
	id, e := s.InventoryRoot("tenant-a")
	if e != nil {
		t.Fatal(e)
	}
	for _, body := range [][]byte{[]byte("short"), []byte("wrong bytes!!"), append(data, 'x')} {
		id, e = s.InventoryRoot("tenant-a")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.StageRepair(ctx, "tenant-a", id, digest, size, bytes.NewReader(body)); e == nil {
			t.Fatal("invalid source accepted")
		}
	}
	id, e = s.InventoryRoot("tenant-a")
	if e != nil {
		t.Fatal(e)
	}
	source, e := s.StageRepair(ctx, "tenant-a", id, digest, size, bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := s.PrepareRepair(ctx, "tenant-a", source, 100, 0)
	if e != nil {
		t.Fatal(e)
	}
	result, e := prepared.Install(ctx)
	prepared.Close()
	if e != nil || result.Before != "missing" || !result.Installed {
		t.Fatal(result, e)
	}
	if _, e = s.PrepareRepair(ctx, "tenant-b", source, 100, 0); e == nil {
		t.Fatal("source crossed tenant")
	}
	sourcePath := filepath.Join(root, "tenant-a", "staged", source.Name)
	if e = os.WriteFile(sourcePath, []byte(strings.Repeat("z", len(data))), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PrepareRepair(ctx, "tenant-a", source, 100, 0); !errors.Is(e, ErrIntegrity) {
		t.Fatal("damaged staged source accepted", e)
	}
}

func TestRepairRejectsChangedTargetAndSourceAfterPrepare(t *testing.T) {
	for _, which := range []string{"source", "target"} {
		t.Run(which, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			s, _ := New(root, 100)
			data := []byte("expected")
			digest := crypt.Digest(data)
			_, e := s.Put(ctx, "tenant-a", bytes.NewReader(data), digest, int64(len(data)))
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, "tenant-a", "sha256", digest[:2], digest)
			if e = os.WriteFile(path, []byte("corrupt!"), 0600); e != nil {
				t.Fatal(e)
			}
			id, _ := s.InventoryRoot("tenant-a")
			source, e := s.StageRepair(ctx, "tenant-a", id, digest, int64(len(data)), bytes.NewReader(data))
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := s.PrepareRepair(ctx, "tenant-a", source, 100, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer prepared.Close()
			change := path
			if which == "source" {
				change = filepath.Join(root, "tenant-a", "staged", source.Name)
			}
			if e = os.WriteFile(change, []byte("changed!"), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = prepared.Install(ctx); !errors.Is(e, ErrStorageChanged) {
				t.Fatal("changed file admitted", e)
			}
		})
	}
}
