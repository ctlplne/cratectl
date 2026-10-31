// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
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
