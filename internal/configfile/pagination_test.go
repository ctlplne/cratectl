// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPaginationKeySurvivesConcurrentPublicationAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pagination.key")
	var wait sync.WaitGroup
	errors := make(chan error, 16)
	for n := 0; n < 16; n++ {
		wait.Add(1)
		go func() { defer wait.Done(); _, e := PaginationKey(path); errors <- e }()
	}
	wait.Wait()
	close(errors)
	for e := range errors {
		if e != nil {
			t.Fatal(e)
		}
	}
	first, e := PaginationKey(path)
	if e != nil {
		t.Fatal(e)
	}
	token, e := first.Seal("context", "position", false)
	if e != nil {
		t.Fatal(e)
	}
	second, e := PaginationKey(path)
	if e != nil {
		t.Fatal(e)
	}
	if p, _, e := second.Open("context", token); e != nil || p != "position" {
		t.Fatal("restart changed key")
	}
	before, _ := os.ReadFile(path)
	if info, e := os.Stat(path); e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key not private")
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = PaginationKey(path); e == nil {
		t.Fatal("public key accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("invalid key replaced")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e = PaginationKey(link); e == nil {
		t.Fatal("linked key accepted")
	}
}
