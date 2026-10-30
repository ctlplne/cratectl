//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"bytes"
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRepairRejectsLinksAndSpecialTargetsWithoutTouchingOutsideBytes(t *testing.T) {
	for _, kind := range []string{"target-link", "source-link", "prefix-link", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			s, _ := New(root, 1024)
			data := []byte("exact retained source")
			digest := crypt.Digest(data)
			_, e := s.Put(ctx, "tenant-a", bytes.NewReader(data), digest, int64(len(data)))
			if e != nil {
				t.Fatal(e)
			}
			id, _ := s.InventoryRoot("tenant-a")
			source, e := s.StageRepair(ctx, "tenant-a", id, digest, int64(len(data)), bytes.NewReader(data))
			if e != nil {
				t.Fatal(e)
			}
			outside := t.TempDir()
			external := filepath.Join(outside, digest)
			unchanged := []byte("outside owned fixture must not change")
			if e = os.WriteFile(external, unchanged, 0600); e != nil {
				t.Fatal(e)
			}
			target := filepath.Join(root, "tenant-a", "sha256", digest[:2], digest)
			switch kind {
			case "target-link":
				if e = os.Remove(target); e == nil {
					e = os.Symlink(external, target)
				}
			case "source-link":
				path := filepath.Join(root, "tenant-a", "staged", source.Name)
				if e = os.Remove(path); e == nil {
					e = os.Symlink(external, path)
				}
			case "prefix-link":
				if e = os.Remove(target); e == nil {
					e = os.Remove(filepath.Dir(target))
				}
				if e == nil {
					e = os.Symlink(outside, filepath.Dir(target))
				}
			case "fifo":
				if e = os.Remove(target); e == nil {
					e = syscall.Mkfifo(target, 0600)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := s.PrepareRepair(ctx, "tenant-a", source, 1024, 0)
			if prepared != nil {
				prepared.Close()
			}
			if !errors.Is(e, ErrUnsupported) {
				t.Fatal("unsupported layout admitted", kind, e)
			}
			after, e := os.ReadFile(external)
			if e != nil || !bytes.Equal(after, unchanged) {
				t.Fatal("external bytes changed", e)
			}
		})
	}
}

func TestRepairRejectsStorageRootRebindingAfterPreparation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, _ := New(root, 1024)
	data := []byte("root bound repair")
	digest := crypt.Digest(data)
	_, e := s.Put(ctx, "tenant-a", bytes.NewReader(data), digest, int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "tenant-a", "sha256", digest[:2], digest)
	bad := bytes.Repeat([]byte("X"), len(data))
	if e = os.WriteFile(target, bad, 0600); e != nil {
		t.Fatal(e)
	}
	id, _ := s.InventoryRoot("tenant-a")
	source, e := s.StageRepair(ctx, "tenant-a", id, digest, int64(len(data)), bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := s.PrepareRepair(ctx, "tenant-a", source, 1024, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer prepared.Close()
	if e = os.Rename(filepath.Join(root, "tenant-a"), filepath.Join(root, "retained-original")); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "tenant-a"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = prepared.Install(ctx); !errors.Is(e, ErrStorageChanged) {
		t.Fatal("storage root rebind admitted", e)
	}
	after, e := os.ReadFile(filepath.Join(root, "retained-original", "sha256", digest[:2], digest))
	if e != nil || !bytes.Equal(after, bad) {
		t.Fatal("old root changed despite fence", e)
	}
}
