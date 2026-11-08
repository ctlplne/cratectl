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

// Transfer only this fixed owned graph after the real source-side assertions.
// Public key fingerprints travel separately through workflow outputs. Private
// signing keys, tokens/configuration, logs and SDK caches are never members.
func writeNativeGoRequirementPortableFixture(t *testing.T, root, collection string, session store.GoRequirementExportSession, head crypt.JournalAnchor, module, selector, lowerInput string) {
	t.Helper()
	requested := os.Getenv("CRATECTL_GO_REQUIREMENT_EXPORT_PORTABLE_OUT")
	if requested == "" {
		return
	}
	destination := filepath.Join(root, ".cache", "go-requirement-export-portable-upload")
	if requested != destination || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("GITHUB_JOB") != "produce" || os.Getenv("GITHUB_REPOSITORY") != "ctlplne/cratectl" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || head.Tenant != "schema-http" || session.Profile != store.GoRequirementExportProfile || session.RootCount != 2 || session.SourceCount != 3 || session.CreatedSequence < 1 || session.CreatedSequence > head.Sequence || !head.Valid() || !store.ValidGoExportID(session.ID) || module != "go.cratectl.invalid/Owned/competing" || selector != "go.cratectl.invalid/Owned/selector" || lowerInput != "input.0000.mod" {
		t.Fatal("requirement portable fixture is restricted to its exact owned native source")
	}
	sha, run, runner := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID"), os.Getenv("RUNNER_NAME")
	if len(sha) != 40 || run == "" || len(run) > 20 || runner == "" || len(runner) > 256 {
		t.Fatal("requirement portable source identity is unavailable")
	}
	for _, char := range sha {
		if !strings.ContainsRune("0123456789abcdef", char) {
			t.Fatal("requirement portable source commit is not canonical")
		}
	}
	for n, char := range run {
		if char < '0' || char > '9' || n == 0 && char == '0' {
			t.Fatal("requirement portable source run is not canonical")
		}
	}
	names := []string{"manifest.json", "journal.jsonl", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "bindings.json", "receipt.json", "main.mod", "requirements.json", "selection.json"}
	for n := range 3 {
		for _, kind := range []string{"manifest.json", "mod"} {
			names = append(names, fmt.Sprintf("input.%04d.%s", n, kind))
		}
	}
	for n := range 2 {
		for _, kind := range []string{"zip", "mod", "info"} {
			names = append(names, fmt.Sprintf("root.%03d.%s", n, kind))
		}
	}
	dir, err := os.Open(collection)
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := dir.Stat()
	entries, readErr := dir.ReadDir(23)
	dir.Close()
	if statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || readErr != nil && readErr != io.EOF || len(entries) != len(names) {
		t.Fatal("requirement capsule needs the exact complete private collection")
	}
	known := make(map[string]bool, len(names))
	for _, name := range names {
		known[name] = true
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			t.Fatal("requirement collection has an unreviewed member")
		}
	}
	data := make(map[string][]byte, len(names))
	var total int
	for _, name := range names {
		raw, err := configfile.ReadBytes(filepath.Join(collection, name), 512<<10, true)
		if err != nil || len(raw) < 1 || bytes.Contains(raw, []byte("PRIVATE KEY")) || len(raw) > (1<<20)-total {
			t.Fatal("owned requirement fixture exceeds its exact public bounds")
		}
		total += len(raw)
		data[name] = raw
	}
	parent, err := store.ParseGoRequirementExportManifest(data["manifest.json"])
	if err != nil || parent.Selection.Tenant != head.Tenant || crypt.Digest(data["manifest.json"]) != session.Manifest.Digest || len(parent.Sources) != 3 || len(parent.Selection.Entries) != 2 || !bytes.Equal(data["main.mod"], []byte("module go.cratectl.invalid/owned-consumer\ngo 1.27.0\nrequire (\n"+module+" v1.0.0\n"+selector+" v1.0.0\n)\n")) {
		t.Fatal("requirement capsule differs from the actual fixed source graph")
	}
	for n, source := range parent.Sources {
		wantModule, wantVersion := module, []string{"v1.0.0", "v1.1.0", "v1.0.0"}[n]
		if n == 2 {
			wantModule = selector
		}
		if source.Repository != "requirements" || source.Module != wantModule || source.Version != wantVersion {
			t.Fatal("requirement capsule contains a nonfixture source coordinate")
		}
		wantMod := "module " + wantModule + "\ngo 1.26\n"
		if n == 2 {
			wantMod = "module " + selector + "\ngo 1.16\nrequire " + module + " v1.1.0\n"
		}
		if !bytes.Equal(data[fmt.Sprintf("input.%04d.mod", n)], []byte(wantMod)) {
			t.Fatal("requirement capsule contains nonfixture metadata bytes")
		}
	}
	fixture := map[string]any{"profile": "cratectl.go.requirement-export.portable.fixture.v1", "candidate": sha, "source_run_id": run, "source_job": "produce", "source_runner_sha256": crypt.Digest([]byte(runner)), "source_os": runtime.GOOS, "source_arch": runtime.GOARCH, "tenant": head.Tenant, "set_id": session.ID, "created_sequence": session.CreatedSequence, "through": head, "module": module, "selector": selector, "lower_input": lowerInput, "examined_sources": 3, "selected_roots": 2, "files": data}
	raw, err := json.Marshal(fixture)
	if err != nil || len(raw)+1 > 2<<20 {
		t.Fatal("owned requirement capsule exceeds its byte bound")
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal("requirement capsule output must be new", err)
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
		t.Fatal("requirement capsule did not sync", err, closeErr)
	}
	for _, path := range []string{destination, filepath.Dir(destination)} {
		directory, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		err = directory.Sync()
		directory.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}
