//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

// Only an explicitly selected disposable CI producer may retain this owned
// input. No customer export, credential, signer private key, log or SDK cache is
// transported. The original single-version fixture and its controls are separate.
func writeNativeGoCommonPortableFixture(t *testing.T, root, collection string, session store.GoExportSetSession, head crypt.JournalAnchor, module string) {
	t.Helper()
	requested := os.Getenv("CRATECTL_GO_COMMON_EXPORT_PORTABLE_OUT")
	if requested == "" {
		return
	}
	destination := filepath.Join(root, ".cache", "go-common-export-portable-upload")
	if requested != destination || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("GITHUB_JOB") != "produce" || os.Getenv("GITHUB_REPOSITORY") != "ctlplne/cratectl" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || head.Tenant != "schema-http" || session.RootCount != 8 || session.CreatedSequence < 1 || session.CreatedSequence > head.Sequence || !head.Valid() || !store.ValidGoExportID(session.ID) || !strings.HasPrefix(module, "go.cratectl.invalid/Owned/") {
		t.Fatal("common portable fixture is restricted to its owned native CI source")
	}
	sha, run, runner := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID"), os.Getenv("RUNNER_NAME")
	if len(sha) != 40 || run == "" || len(run) > 20 || runner == "" || len(runner) > 256 {
		t.Fatal("common portable source identity is unavailable")
	}
	for _, char := range sha {
		if !strings.ContainsRune("0123456789abcdef", char) {
			t.Fatal("common portable source commit is not canonical")
		}
	}
	for n, char := range run {
		if char < '0' || char > '9' || n == 0 && char == '0' {
			t.Fatal("common portable source run is not canonical")
		}
	}
	names := []string{"manifest.json", "journal.jsonl", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "bindings.json", "receipt.json"}
	for n := range 8 {
		for _, kind := range []string{"zip", "mod", "info"} {
			names = append(names, fmt.Sprintf("root.%03d.%s", n, kind))
		}
	}
	dir, err := os.Open(collection)
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := dir.Stat()
	entries, readErr := dir.ReadDir(32)
	dir.Close()
	if statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || readErr != nil && readErr != io.EOF || len(entries) != len(names) {
		t.Fatal("common capsule requires the exact complete private collection")
	}
	known := make(map[string]bool, len(names))
	for _, name := range names {
		known[name] = true
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			t.Fatal("common collection has an unreviewed retained member")
		}
	}
	data := make(map[string][]byte, len(names))
	var total int
	for _, name := range names {
		raw, err := configfile.ReadBytes(filepath.Join(collection, name), 512<<10, true)
		if err != nil || len(raw) < 1 || bytes.Contains(raw, []byte("PRIVATE KEY")) || len(raw) > (1<<20)-total {
			t.Fatal("owned common fixture exceeds its exact public input bounds")
		}
		total += len(raw)
		data[name] = raw
	}
	fixture := map[string]any{"profile": "cratectl.go.common-export.portable.fixture.v1", "candidate": sha, "source_run_id": run, "source_job": "produce", "source_runner_sha256": crypt.Digest([]byte(runner)), "source_os": runtime.GOOS, "source_arch": runtime.GOARCH, "tenant": head.Tenant, "set_id": session.ID, "created_sequence": session.CreatedSequence, "through": head, "root_module": module, "root_count": 8, "files": data}
	raw, err := json.Marshal(fixture)
	if err != nil || len(raw)+1 > 2<<20 {
		t.Fatal("owned common capsule exceeds its byte bound")
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal("common capsule output must be a new private directory", err)
	}
	file, err := os.OpenFile(filepath.Join(destination, "fixture.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.Write(append(raw, '\n'))
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("common capsule bytes did not sync", err, closeErr)
	}
	directory, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(filepath.Dir(destination))
	if err != nil {
		t.Fatal(err)
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		t.Fatal(err)
	}
}
