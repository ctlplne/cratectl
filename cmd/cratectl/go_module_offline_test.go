// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

func offlineGoFiles(t *testing.T) (store.GoHostedPublication, [3][]byte) {
	t.Helper()
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/offline", Version: "v1.0.0"}
	mod := []byte("module " + c.Module + "\n\ngo 1.26.0\n")
	info, err := gomodule.VersionInfo(c, "2026-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	z := zip.NewWriter(&body)
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"go.mod", mod}, {"assets/owned.txt", []byte("inert original bytes")}} {
		w, err := z.Create(c.Module + "@" + c.Version + "/" + item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(item.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	files := [3][]byte{body.Bytes(), mod, info}
	p := store.GoHostedPublication{Tenant: "owned-team", Repository: "owned", Coordinate: c, ZIP: crypt.Digest(files[0]), Mod: crypt.Digest(files[1]), Info: crypt.Digest(files[2])}
	return p, files
}

func TestOfflineGoStagesExactPrivateBytesBeforePublishingProxy(t *testing.T) {
	for _, scenario := range []string{"original", "existing-output", "zip-changed", "mod-changed", "info-changed", "signed-invalid-zip", "signed-invalid-mod", "signed-invalid-info", "mismatched-zip-mod", "wrong-coordinate", "symlink-input", "public-input", "public-parent", "symlink-parent", "missing-input", "cancelled", "invalid-digest"} {
		t.Run(scenario, func(t *testing.T) {
			p, files := offlineGoFiles(t)
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "zip-changed":
				files[0] = append(bytes.Clone(files[0]), 'x')
			case "mod-changed":
				files[1] = append(bytes.Clone(files[1]), 'x')
			case "info-changed":
				files[2] = append(bytes.Clone(files[2]), 'x')
			case "signed-invalid-zip":
				files[0] = []byte("not an archive")
				p.ZIP = crypt.Digest(files[0])
			case "signed-invalid-mod":
				files[1] = []byte("not a module")
				p.Mod = crypt.Digest(files[1])
			case "signed-invalid-info":
				files[2] = []byte(`{"Version":"v1.1.0"}`)
				p.Info = crypt.Digest(files[2])
			case "mismatched-zip-mod":
				files[1] = append(bytes.Clone(files[1]), []byte("// other bytes\n")...)
				p.Mod = crypt.Digest(files[1])
			case "wrong-coordinate":
				p.Coordinate.Module += "/other"
			case "invalid-digest":
				p.Mod = "bad"
			}
			var inputs [3]string
			for n, kind := range []string{"zip", "mod", "info"} {
				inputs[n] = filepath.Join(dir, "original."+kind)
				if err := os.WriteFile(inputs[n], files[n], 0600); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(dir, "offline")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "existing-output":
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, "sentinel"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-input":
				link := filepath.Join(dir, "link")
				if err := os.Symlink(inputs[0], link); err != nil {
					t.Fatal(err)
				}
				inputs[0] = link
			case "public-input":
				if err := os.Chmod(inputs[1], 0644); err != nil {
					t.Fatal(err)
				}
			case "public-parent":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				link := filepath.Join(dir, "parent-link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(link, "offline")
			case "missing-input":
				inputs[2] += "-missing"
			case "cancelled":
				cancel()
			}
			receipt, err := prepareOfflineGo(ctx, p, nil, inputs, output)
			if scenario != "original" {
				if err == nil || receipt.Profile != "" {
					t.Fatal("failed preparation produced receipt", scenario, err)
				}
				if scenario == "existing-output" {
					raw, err := os.ReadFile(filepath.Join(output, "sentinel"))
					if err != nil || string(raw) != "keep" {
						t.Fatal("existing output changed", err)
					}
				} else if _, err := os.Lstat(output); !os.IsNotExist(err) {
					t.Fatal("failed output survived", scenario, err)
				}
				return
			}
			if err != nil || receipt.ZIPHash == "" || receipt.ModHash == "" || receipt.CurrentRegistryAdmission || receipt.ChecksumAuthority {
				t.Fatal("original inert bytes rejected or admission invented", err)
			}
			for n, kind := range []string{"zip", "mod", "info"} {
				path := filepath.Join(output, "proxy", p.Coordinate.Prefix()+"."+kind)
				raw, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, files[n]) {
					t.Fatal("native representation changed", kind, err)
				}
				st, err := os.Stat(path)
				if err != nil || st.Mode().Perm() != 0600 {
					t.Fatal("public native bytes", err)
				}
			}
			var saved goOfflineReceipt
			raw, err := os.ReadFile(filepath.Join(output, "receipt.json"))
			if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Proxy != receipt.Proxy || !strings.HasPrefix(saved.Proxy, "file://") {
				t.Fatal("durable exact receipt missing", err)
			}
			if _, err := os.Stat(filepath.Join(output, "staging")); !os.IsNotExist(err) {
				t.Fatal("staging path retained")
			}
		})
	}
}

func TestOfflineGoCommandRequiresSignedOriginalPublicationBeforeOutput(t *testing.T) {
	for _, args := range [][]string{{}, {"--repository", "owned", "--module", "go.cratectl.invalid/owned", "--version", "v1.0.0"}, {"--journal-file", "missing", "--repository", "owned", "--module", "go.cratectl.invalid/owned", "--version", "v1.0.0", "--zip-file", "missing", "--mod-file", "missing", "--info-file", "missing", "--output-directory", "missing"}} {
		var out bytes.Buffer
		if err := runGoModuleOffline(args, &out); err == nil || out.Len() != 0 {
			t.Fatal("incomplete offline input produced receipt", err)
		}
	}
}
