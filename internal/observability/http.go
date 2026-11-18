// SPDX-License-Identifier: BUSL-1.1
package observability

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"ctlplne.dev/cratectl/internal/crypto"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

var protocols = [...]string{"management", "files", "npm", "pypi", "oci", "nuget", "go", "health", "console", "other"}
var outcomes = [...]string{"success", "redirect", "auth_denied", "client_error", "server_error", "aborted"}
var upperBounds = [...]time.Duration{
	5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond,
	time.Second, 5 * time.Second, 30 * time.Second,
}

type traffic struct {
	requests [len(outcomes)]uint64
	buckets  [len(upperBounds)]uint64
	active   uint64
	count    uint64
	received uint64
	sent     uint64
	seconds  float64
}

type Metrics struct {
	next      http.Handler
	token     crypto.TokenDigest
	admission func() (inUse, capacity int, rejected uint64)
	mu        sync.Mutex
	protocols [len(protocols)]traffic
}

func NewHTTP(next http.Handler, token []byte, admission func() (int, int, uint64)) (*Metrics, error) {
	if next == nil || admission == nil {
		return nil, errors.New("metrics requires a registry handler and admission counters")
	}
	value := bytes.TrimSpace(token)
	if !tokenPattern.Match(value) {
		return nil, errors.New("metrics token must be a private 32–256 character base64url value")
	}
	return &Metrics{next: next, token: crypto.DigestToken(value), admission: admission}, nil
}

func protocol(path string) int {
	first, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	switch first {
	case "api":
		return 0
	case "r":
		return 1
	case "npm":
		return 2
	case "pypi":
		return 3
	case "v2":
		return 4
	case "nuget":
		return 5
	case "go":
		return 6
	case "health":
		return 7
	case "console", "":
		return 8
	default:
		return 9
	}
}

func outcome(status int, completed bool) int {
	if !completed {
		return 5
	}
	switch {
	case status == 0 || status >= 200 && status < 300:
		return 0
	case status >= 300 && status < 400:
		return 1
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return 2
	case status >= 400 && status < 500:
		return 3
	default:
		return 4
	}
}

type requestBody struct {
	io.ReadCloser
	bytes uint64
}

func (b *requestBody) Read(output []byte) (int, error) {
	n, err := b.ReadCloser.Read(output)
	b.bytes += uint64(n)
	return n, err
}

type responseBody struct {
	http.ResponseWriter
	status int
	bytes  uint64
}

func (w *responseBody) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseBody) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	if status >= 200 && w.status == 0 {
		w.status = status
	}
}

func (w *responseBody) Write(value []byte) (int, error) {
	n, err := w.ResponseWriter.Write(value)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += uint64(n)
	return n, err
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/metrics" {
		m.scrape(w, r)
		return
	}
	lane := protocol(r.URL.Path)
	m.mu.Lock()
	m.protocols[lane].active++
	m.mu.Unlock()
	start := time.Now()
	response := &responseBody{ResponseWriter: w}
	body := &requestBody{ReadCloser: r.Body}
	if r.Body != nil && r.Body != http.NoBody {
		observed := *r
		observed.Body = body
		r = &observed
	}
	completed := false
	defer func() {
		elapsed := time.Since(start)
		m.mu.Lock()
		current := &m.protocols[lane]
		current.active--
		current.count++
		current.requests[outcome(response.status, completed)]++
		current.received += body.bytes
		if r.Method != http.MethodHead {
			current.sent += response.bytes
		}
		current.seconds += elapsed.Seconds()
		for i, ceiling := range upperBounds {
			if elapsed <= ceiling {
				current.buckets[i]++
				break
			}
		}
		m.mu.Unlock()
	}()
	m.next.ServeHTTP(response, r)
	completed = true
}

func (m *Metrics) scrape(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	headers := r.Header.Values("Authorization")
	token := ""
	if len(headers) == 1 && len(headers[0]) <= 263 {
		scheme, value, found := strings.Cut(headers[0], " ")
		if found && strings.EqualFold(scheme, "Bearer") {
			token = value
		}
	}
	if r.TLS == nil || len(token) < 32 || !m.token.Matches(token) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "A TLS metrics credential is required.", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Use GET to read metrics.", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "Read metrics without query parameters.", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	snapshot := m.protocols
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	body := &strings.Builder{}
	body.Grow(32 << 10)
	fmt.Fprintln(body, "# HELP cratectl_http_requests_total Completed or aborted HTTP requests by fixed protocol and outcome.")
	fmt.Fprintln(body, "# TYPE cratectl_http_requests_total counter")
	for i, name := range protocols {
		for j, status := range outcomes {
			fmt.Fprintf(body, "cratectl_http_requests_total{protocol=%q,outcome=%q} %d\n", name, status, snapshot[i].requests[j])
		}
	}
	fmt.Fprintln(body, "# HELP cratectl_http_request_duration_seconds Time spent handling a request.")
	fmt.Fprintln(body, "# TYPE cratectl_http_request_duration_seconds histogram")
	for i, name := range protocols {
		samples := snapshot[i]
		var cumulative uint64
		for j, ceiling := range upperBounds {
			cumulative += samples.buckets[j]
			fmt.Fprintf(body, "cratectl_http_request_duration_seconds_bucket{protocol=%q,le=%q} %d\n", name,
				fmt.Sprint(ceiling.Seconds()), cumulative)
		}
		fmt.Fprintf(body, "cratectl_http_request_duration_seconds_bucket{protocol=%q,le=\"+Inf\"} %d\n", name, samples.count)
		fmt.Fprintf(body, "cratectl_http_request_duration_seconds_sum{protocol=%q} %g\n", name, samples.seconds)
		fmt.Fprintf(body, "cratectl_http_request_duration_seconds_count{protocol=%q} %d\n", name, samples.count)
	}
	fmt.Fprintln(body, "# HELP cratectl_http_request_body_bytes_total Bytes read by application request handlers.")
	fmt.Fprintln(body, "# TYPE cratectl_http_request_body_bytes_total counter")
	for i, name := range protocols {
		fmt.Fprintf(body, "cratectl_http_request_body_bytes_total{protocol=%q} %d\n", name, snapshot[i].received)
	}
	fmt.Fprintln(body, "# HELP cratectl_http_response_body_bytes_total Body bytes written by HTTP handlers.")
	fmt.Fprintln(body, "# TYPE cratectl_http_response_body_bytes_total counter")
	for i, name := range protocols {
		fmt.Fprintf(body, "cratectl_http_response_body_bytes_total{protocol=%q} %d\n", name, snapshot[i].sent)
	}
	fmt.Fprintln(body, "# HELP cratectl_http_requests_in_flight Current application request handlers.")
	fmt.Fprintln(body, "# TYPE cratectl_http_requests_in_flight gauge")
	for i, name := range protocols {
		fmt.Fprintf(body, "cratectl_http_requests_in_flight{protocol=%q} %d\n", name, snapshot[i].active)
	}
	inUse, capacity, rejected := m.admission()
	fmt.Fprintf(body, "# HELP cratectl_transfer_admitted Current admitted registry requests.\n# TYPE cratectl_transfer_admitted gauge\ncratectl_transfer_admitted %d\n", inUse)
	fmt.Fprintf(body, "# HELP cratectl_transfer_capacity Configured registry admission slots.\n# TYPE cratectl_transfer_capacity gauge\ncratectl_transfer_capacity %d\n", capacity)
	fmt.Fprintf(body, "# HELP cratectl_transfer_rejected_total Registry requests refused because all admission slots were in use.\n# TYPE cratectl_transfer_rejected_total counter\ncratectl_transfer_rejected_total %d\n", rejected)
	_, _ = io.WriteString(w, body.String())
}
