// SPDX-License-Identifier: BUSL-1.1
package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fixtureToken = "cratectl-owned-metrics-fixture-32"

func TestMetricsUsesDedicatedTLSCredentialAndFixedSeries(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, "stored")
			return
		}
		http.Error(w, "owned response private content", 403)
	})
	metrics, err := NewHTTP(next, []byte(fixtureToken+"\n"), func() (int, int, uint64) { return 1, 16, 3 })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(metrics)
	defer server.Close()
	perform := func(method, path, payload string, auth ...string) (int, http.Header, string) {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range auth {
			request.Header.Add("Authorization", value)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, string(data)
	}
	for _, auth := range [][]string{nil, {"Bearer owned-unrelated-registry-token"}, {"Bearer " + fixtureToken, "Bearer duplicate"}} {
		code, _, body := perform("GET", "/metrics", "", auth...)
		if code != 401 || strings.Contains(body, "cratectl_http_") {
			t.Fatal("unauthorized scrape received process metrics")
		}
	}
	if code, _, _ := perform("POST", "/metrics", "", "Bearer "+fixtureToken); code != 405 {
		t.Fatal("scrape method constraint failed", code)
	}
	if code, _, _ := perform("GET", "/metrics?owned=ignored", "", "Bearer "+fixtureToken); code != 400 {
		t.Fatal("scrape query constraint failed", code)
	}
	if code, _, body := perform("PUT", "/r/owned-repo/owned-path?q=owned-query", "contents"); code != 201 || body != "stored" {
		t.Fatalf("wrapped upload changed the result %d %q", code, body)
	}
	if code, _, _ := perform("GET", "/r/owned-repo/owned-path", "", "Bearer owned-identity"); code != 403 {
		t.Fatal("wrapped denial changed the original status")
	}
	code, headers, text := perform("GET", "/metrics", "", "bEaReR "+fixtureToken)
	if code != 200 || headers.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || !strings.HasSuffix(text, "\n") {
		t.Fatal("invalid scrape status or content type")
	}
	for _, expected := range []string{
		`cratectl_http_requests_total{protocol="files",outcome="success"} 1`,
		`cratectl_http_requests_total{protocol="files",outcome="auth_denied"} 1`,
		`cratectl_http_request_duration_seconds_count{protocol="files"} 2`,
		`cratectl_http_request_duration_seconds_bucket{protocol="files",le="+Inf"} 2`,
		`cratectl_http_request_body_bytes_total{protocol="files"} 8`,
		"cratectl_transfer_admitted 1", "cratectl_transfer_capacity 16", "cratectl_transfer_rejected_total 3",
	} {
		if !strings.Contains(text, expected+"\n") {
			t.Errorf("missing exact metric %s", expected)
		}
	}
	for _, private := range []string{fixtureToken, "owned-repo", "owned-path", "owned-query", "owned-identity", "private content"} {
		if strings.Contains(text, private) {
			t.Fatalf("scrape included request-specific data %q", private)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+fixtureToken)
	metrics.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("plaintext scrape returned HTTP %d", w.Code)
	}
}

func TestObservedWriterPreservesResponseControllerAndPanic(t *testing.T) {
	metrics, err := NewHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go/abort" {
			panic("owned handler stopped")
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, "ok")
	}), []byte(fixtureToken), func() (int, int, uint64) { return 0, 1, 0 })
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	metrics.ServeHTTP(w, httptest.NewRequest("GET", "/go/valid", nil))
	if !w.Flushed || w.Body.String() != "ok" {
		t.Fatal("instrumentation changed response controller or body")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("instrumentation swallowed the handler failure")
			}
		}()
		metrics.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/go/abort", nil))
	}()
	got := metrics.protocols[protocol("/go/valid")]
	if got.count != 2 || got.active != 0 || got.requests[outcome(200, true)] != 1 || got.requests[outcome(0, false)] != 1 {
		t.Fatalf("unexpected request observations %+v", got)
	}
}
