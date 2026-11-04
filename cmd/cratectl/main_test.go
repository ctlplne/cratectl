// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func runCLIResponseFixture(t *testing.T, body string, args ...string) (error, int64) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/known-length" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	directory := t.TempDir()
	credential := filepath.Join(directory, "client.token")
	if e := os.WriteFile(credential, []byte(strings.Repeat("x", 32)), 0600); e != nil {
		t.Fatal(e)
	}
	output, e := os.Create(filepath.Join(directory, "response.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer output.Close()
	originalArgs, originalOut := os.Args, os.Stdout
	defer func() { os.Args = originalArgs; os.Stdout = originalOut }()
	os.Args = append([]string{"cratectl", "--url", server.URL, "--token-file", credential, "--path", "/api/v1/response-fixture"}, args...)
	os.Stdout = output
	result := run()
	info, e := output.Stat()
	if e != nil {
		t.Fatal(e)
	}
	return result, info.Size()
}
func TestCLIRejectsAnIncompleteOversizedManagementResponse(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", (4<<20)+64) + `"}`
	e, n := runCLIResponseFixture(t, body)
	if e == nil {
		t.Fatalf("oversized management response returned success with %d output bytes for a %d-byte JSON document", n, len(body))
	}
	if e, n := runCLIResponseFixture(t, body, "--path", "/api/v1/known-length"); e == nil || n != 0 {
		t.Fatal("known oversized document printed or acknowledged", e, n)
	}
}

func TestCLIExplicitResponseBudgetReturnsTheWholeLargeDocument(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", (4<<20)+64) + `"}`
	e, n := runCLIResponseFixture(t, body, "--response-limit", "8388608")
	if e != nil || n != int64(len(body)+1) {
		t.Fatal("complete explicit-budget response", e, n)
	}
	for _, limit := range []string{"0", "-1", "1073741825"} {
		if e, n := runCLIResponseFixture(t, `{}`, "--response-limit", limit); e == nil || n != 0 {
			t.Fatal("invalid response budget accepted", limit, e, n)
		}
	}
}

type countedResponse struct {
	io.Reader
	read int
}

func (r *countedResponse) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.read += n
	return n, e
}

type brokenResponse struct{}

func (brokenResponse) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestManagementResponseCopyBoundsWorkAndPropagatesFailures(t *testing.T) {
	for _, size := range []int{0, 63, 64, 65, 1024} {
		body := strings.Repeat("x", size)
		input := &countedResponse{Reader: strings.NewReader(body)}
		var out strings.Builder
		e := copyManagementResponse(&out, input, 64)
		if size <= 64 {
			if e != nil || out.String() != body {
				t.Fatal("complete boundary response", size, e)
			}
		} else {
			if e == nil || out.Len() != 64 || input.read != 65 {
				t.Fatal("response consumed or printed beyond its bounded prefix", size, e, out.Len(), input.read)
			}
		}
	}
	if e := copyManagementResponse(io.Discard, brokenResponse{}, 64); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal("read failure acknowledged", e)
	}
}

func TestCLIGoModuleUploadUsesConfiguredTLSAndExactPublicationBytes(t *testing.T) {
	directory := t.TempDir()
	body := "owned inert ZIP upload stand-in\x00\xff"
	token := strings.Repeat("x", 32)
	path := "/go/owned/example.org/!owned/application/v2/@v/v2.1.0.zip"
	instant := "2026-01-02T03:04:05Z"
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		data, e := io.ReadAll(r.Body)
		if e != nil || string(data) != body || r.ContentLength != int64(len(body)) || r.Method != "PUT" || r.URL.RequestURI() != path {
			t.Error("CLI changed upload bytes, declared length, method or canonical coordinate", e)
		}
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-Cratectl-Module-Time") != instant || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Idempotency-Key") != "owned-retry" {
			t.Error("CLI lost configured authentication, stable instant or retry identity")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"version":"v2.1.0"}`)
	}))
	defer server.Close()
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(directory, name)
		if e := os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	credential := write("client.token", []byte(token))
	ca := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	zip := write("module.zip", []byte(body))
	configuration := write("client.json", []byte(fmt.Sprintf(`{"version":1,"url":%q,"token_file":%q,"ca_file":%q}`, server.URL, credential, ca)))
	output, e := os.Create(filepath.Join(directory, "response.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer output.Close()
	originalArgs, originalOut := os.Args, os.Stdout
	defer func() { os.Args = originalArgs; os.Stdout = originalOut }()
	os.Args = []string{"cratectl", "--config", configuration, "--method", "PUT", "--path", path, "--upload-file", zip, "--go-module-time", instant, "--idempotency-key", "owned-retry"}
	os.Stdout = output
	if e := run(); e != nil {
		t.Fatal("configured Go publication failed before reaching the owned TLS stand-in", e)
	}
	if requests != 1 {
		t.Fatal("expected exactly one publication request", requests)
	}
	data, e := os.ReadFile(output.Name())
	if e != nil || string(data) != "{\"version\":\"v2.1.0\"}\n" {
		t.Fatal("complete publication receipt", e)
	}
}

func TestCLIGoPublicationRejectsOtherRoutesAndAmbiguousCoordinates(t *testing.T) {
	path := "/go/owned/example.org/!owned/application/@v/v1.0.0.zip"
	instant := "2026-01-02T03:04:05Z"
	for _, change := range []struct{ name, path, method, upload, instant string }{
		{"missing time", path, "PUT", "owned.zip", ""},
		{"missing upload", path, "PUT", "", instant},
		{"read", path, "GET", "owned.zip", instant},
		{"delete", path, "DELETE", "owned.zip", instant},
		{"metadata", strings.TrimSuffix(path, ".zip") + ".mod", "PUT", "owned.zip", instant},
		{"list", "/go/owned/example.org/app/@v/list", "PUT", "owned.zip", instant},
		{"other protocol", "/r/owned/object.zip", "PUT", "owned.zip", instant},
		{"management", "/api/v1/repositories", "PUT", "owned.zip", instant},
		{"bad repository", strings.Replace(path, "/owned/", "/Owned/", 1), "PUT", "owned.zip", instant},
		{"long repository", strings.Replace(path, "/owned/", "/"+strings.Repeat("a", 64)+"/", 1), "PUT", "owned.zip", instant},
		{"traversal", strings.Replace(path, "/owned/", "/../", 1), "PUT", "owned.zip", instant},
		{"module traversal", "/go/owned/example.org/../app/@v/v1.0.0.zip", "PUT", "owned.zip", instant},
		{"literal uppercase", strings.Replace(path, "!owned", "Owned", 1), "PUT", "owned.zip", instant},
		{"percent alias", strings.Replace(path, "!owned", "%21owned", 1), "PUT", "owned.zip", instant},
		{"query", path + "?other=1", "PUT", "owned.zip", instant},
		{"fragment", path + "#other", "PUT", "owned.zip", instant},
		{"noncanonical version", strings.Replace(path, "v1.0.0", "v1.0", 1), "PUT", "owned.zip", instant},
		{"wrong major", strings.Replace(path, "v1.0.0", "v2.0.0", 1), "PUT", "owned.zip", instant},
		{"zero time", path, "PUT", "owned.zip", "0001-01-01T00:00:00Z"},
		{"bad time", path, "PUT", "owned.zip", "yesterday"},
		{"pseudo time mismatch", strings.Replace(path, "v1.0.0", "v0.0.0-20260102030406-0123456789ab", 1), "PUT", "owned.zip", instant},
	} {
		t.Run(change.name, func(t *testing.T) {
			if e := validateClientPath(change.path, change.method, change.upload, change.instant); e == nil {
				t.Fatal("invalid publication accepted")
			}
		})
	}
	if e := validateClientPath("/api/v1/repositories", "GET", "", ""); e != nil {
		t.Fatal("ordinary management requests changed", e)
	}
	pseudo := strings.Replace(path, "v1.0.0", "v0.0.0-20260102030405-0123456789ab", 1)
	if e := validateClientPath(pseudo, "PUT", "owned.zip", instant); e != nil {
		t.Fatal("matching pseudo-version publication rejected", e)
	}
}
