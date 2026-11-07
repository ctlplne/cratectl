// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type importRoundTrip func(*http.Request) (*http.Response, error)

func (f importRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoImportRequiresExactSourceAndBoundedDestinationReceipt(t *testing.T) {
	for _, scenario := range []string{"original", "lost-response", "denied", "conflict", "redirect", "compressed", "wrong-digest", "wrong-repository", "unknown-field", "duplicate-field", "large-response", "changed-info", "noncanonical-info", "changed-zip", "shared-zip", "existing-intent"} {
		t.Run(scenario, func(t *testing.T) {
			p, files := offlineGoFiles(t)
			if scenario == "noncanonical-info" {
				files[2] = append(files[2], '\n')
				p.Info = crypt.Digest(files[2])
			}
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			var inputs [3]string
			for n, kind := range []string{"zip", "mod", "info"} {
				inputs[n] = filepath.Join(parent, "original."+kind)
				if err := os.WriteFile(inputs[n], files[n], 0600); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(parent, "attempt")
			prepared, err := prepareOfflineGo(context.Background(), p, nil, inputs, output)
			if err != nil {
				t.Fatal(err)
			}
			zipPath := filepath.Join(output, "proxy", p.Coordinate.Prefix()+".zip")
			switch scenario {
			case "changed-info":
				if err := os.WriteFile(filepath.Join(output, "proxy", p.Coordinate.Prefix()+".info"), []byte(`{"Version":"v1.0.0","Time":"2026-02-02T03:04:05Z"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-zip":
				if err := os.WriteFile(zipPath, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "shared-zip":
				if err := os.Link(zipPath, filepath.Join(parent, "outside-link")); err != nil {
					t.Fatal(err)
				}
			case "existing-intent":
				if err := os.WriteFile(filepath.Join(output, "import-intent.json"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			client := &http.Client{Transport: importRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "PUT" || r.URL.String() != "https://destination.cratectl.invalid/go/destination/"+p.Coordinate.Prefix()+".zip" || r.Header.Get("Authorization") != "Bearer owned-unit-token" || r.Header.Get("Idempotency-Key") != "owned-import-key" || r.Header.Get("X-Cratectl-Module-Time") != "2026-01-02T03:04:05Z" || r.Header.Get("X-Checksum-Sha256") != p.ZIP || r.ContentLength != int64(len(files[0])) {
					t.Fatal("destination request lost exact bindings")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(body, files[0]) {
					t.Fatal("destination upload changed bytes", err)
				}
				intent, err := os.ReadFile(filepath.Join(output, "import-intent.json"))
				if err != nil || bytes.Contains(intent, []byte("owned-unit-token")) {
					t.Fatal("durable nonsecret intent missing", err)
				}
				if scenario == "lost-response" {
					return nil, errors.New("owned transport interruption")
				}
				publication := goImportPublication{p.Coordinate.Module, "destination", map[string]string{"zip": p.ZIP, "mod": p.Mod, "info": p.Info}, p.Coordinate.Version}
				if scenario == "wrong-digest" {
					publication.Representations["zip"] = strings.Repeat("f", 64)
				}
				if scenario == "wrong-repository" {
					publication.Repository = "other"
				}
				raw := bytes.TrimSuffix(collectionJSON(publication), []byte("\n"))
				status := 201
				header := http.Header{}
				switch scenario {
				case "denied":
					status = 403
				case "conflict":
					status = 409
				case "redirect":
					status = 307
				case "compressed":
					header.Set("Content-Encoding", "gzip")
				case "unknown-field":
					raw = append(raw[:len(raw)-1], []byte(`,"admitted":true}`)...)
				case "duplicate-field":
					raw = append([]byte(`{"module":"wrong",`), raw[1:]...)
				case "large-response":
					raw = bytes.Repeat([]byte("x"), collectionJSONLimit+1)
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			receipt, err := importPreparedGo(context.Background(), client, "https://destination.cratectl.invalid", "owned-unit-token", "destination", "owned-import-key", output, prepared)
			if scenario == "original" {
				if err != nil || !receipt.PublicationRecorded || receipt.CurrentRegistryAdmission || receipt.ChecksumAuthority || receipt.DependencyClosure || calls != 1 {
					t.Fatal("wrong import scope", err)
				}
				saved, err := os.ReadFile(filepath.Join(output, "import-receipt.json"))
				if err != nil || !bytes.Equal(saved, collectionJSON(receipt)) {
					t.Fatal("complete receipt missing", err)
				}
			} else {
				if err == nil || receipt.PublicationRecorded {
					t.Fatal("unconfirmed publication accepted", scenario)
				}
				if _, err := os.Stat(filepath.Join(output, "import-receipt.json")); !os.IsNotExist(err) {
					t.Fatal("failed import wrote final receipt")
				}
				beforeNetwork := scenario == "changed-info" || scenario == "noncanonical-info" || scenario == "changed-zip" || scenario == "shared-zip" || scenario == "existing-intent"
				if beforeNetwork && calls != 0 || !beforeNetwork && calls != 1 {
					t.Fatal("unexpected request/retry", calls)
				}
			}
			if scenario == "existing-intent" {
				raw, _ := os.ReadFile(filepath.Join(output, "import-intent.json"))
				if string(raw) != "keep" {
					t.Fatal("existing intent overwritten")
				}
			}
		})
	}
}

func TestGoImportCLIRequiresSignedSourceBeforeDestinationAccess(t *testing.T) {
	var out bytes.Buffer
	if err := runGoExportImport([]string{"--config", "missing", "--repository", "source", "--destination-repository", "destination", "--module", "go.cratectl.invalid/Owned/offline", "--version", "v1.0.0", "--manifest-file", "missing", "--export-id", strings.Repeat("a", 64), "--zip-file", "missing", "--mod-file", "missing", "--info-file", "missing", "--output-directory", "missing", "--idempotency-key", "owned"}, &out); err == nil || out.Len() != 0 {
		t.Fatal("missing signed source accepted")
	}
}
