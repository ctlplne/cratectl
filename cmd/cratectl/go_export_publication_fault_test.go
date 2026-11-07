//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A disposable unit child alone gets this kernel file limit. It invokes no
// registry, signer, SDK or network command, and cannot change the parent limit.
func TestMain(m *testing.M) {
	if path := os.Getenv("CRATECTL_COLLECTION_WRITE_FAULT_CHILD"); path != "" {
		root, dir, err := openCollectionDirectory(path, false)
		if err != nil {
			os.Exit(3)
		}
		kind := os.Getenv("CRATECTL_COLLECTION_WRITE_FAULT_KIND")
		binding := collectionBinding{Profile: goCollectionProfile, Authority: "https://cratectl.invalid", ExportID: strings.Repeat("a", 64)}
		if kind == "receipt" {
			if err := bindCollection(root, binding, false); err != nil {
				os.Exit(6)
			}
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 128, Max: 128}); err != nil {
			os.Exit(4)
		}
		if kind == "receipt" {
			_, err = publishCollectionReceipt(root, binding, 7, false)
		} else {
			err = bindCollection(root, binding, false)
		}
		dir.Close()
		root.Close()
		if err == nil {
			os.Exit(5)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func TestCollectionFailedMetadataWriteDoesNotPublishFinalName(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "collection")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	before := new(syscall.Rlimit)
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, before); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^$")
	cmd.Env = append(os.Environ(), "CRATECTL_COLLECTION_WRITE_FAULT_CHILD="+output, "CRATECTL_COLLECTION_WRITE_FAULT_KIND=binding")
	var diagnostic bytes.Buffer
	cmd.Stdout = &diagnostic
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		t.Fatalf("owned file-limit child: %v, %q", err, diagnostic.Bytes())
	}
	after := new(syscall.Rlimit)
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, after); err != nil || *before != *after {
		t.Fatal("child changed parent file limit", err)
	}
	if info, err := os.Stat(filepath.Join(output, "bindings.json")); !os.IsNotExist(err) {
		if err == nil {
			t.Fatalf("failed metadata write published incomplete final bindings.json (%dbytes)", info.Size())
		}
		t.Fatal(err)
	}
}

func TestCollectionFailedReceiptWriteStaysPendingAndCanResume(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "collection")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^$")
	cmd.Env = append(os.Environ(), "CRATECTL_COLLECTION_WRITE_FAULT_CHILD="+output, "CRATECTL_COLLECTION_WRITE_FAULT_KIND=receipt")
	var diagnostic bytes.Buffer
	cmd.Stdout = &diagnostic
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		t.Fatalf("owned receipt file-limit child: %v %q", err, diagnostic.Bytes())
	}
	if _, err := os.Stat(filepath.Join(output, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("failed receipt write exposed final name")
	}
	partial, err := os.ReadFile(filepath.Join(output, "receipt.7.pending"))
	if err != nil || len(partial) != 128 {
		t.Fatal("pending receipt checkpoint lost", err, len(partial))
	}
	root, dir, err := openCollectionDirectory(output, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer dir.Close()
	binding := collectionBinding{Profile: goCollectionProfile, Authority: "https://cratectl.invalid", ExportID: strings.Repeat("a", 64)}
	receipt, err := publishCollectionReceipt(root, binding, 8, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receipt, collectionJSON(goCollectionReceipt{Binding: binding, CollectedGeneration: 7, BytesVerified: true})) {
		t.Fatal("renewal changed pending completion generation")
	}
}
