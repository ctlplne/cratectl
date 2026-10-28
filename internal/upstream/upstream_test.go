// SPDX-License-Identifier: BUSL-1.1
package upstream

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"testing"
)

func TestDestinationAndCredentialBoundary(t *testing.T) {
	leaked := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer configured-private-token" {
			t.Error("configured credential missing")
		}
		if strings.HasSuffix(r.URL.Path, "redirect") {
			http.Redirect(w, r, other.URL+"/sink", 302)
			return
		}
		io.WriteString(w, "exact bytes")
	}))
	defer origin.Close()
	e, err := New(Config{URL: origin.URL + "/base/", Networks: []string{"127.0.0.1/32"}}, "configured-private-token", "127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	response, err := e.Get(context.Background(), "pkg/file", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(b) != "exact bytes" {
		t.Fatal("wrong response")
	}
	if _, err = e.Get(context.Background(), "redirect", nil); err == nil {
		t.Fatal("cross-authority redirect accepted")
	}
	if leaked {
		t.Fatal("credential reached another authority")
	}
	denied, err := New(Config{URL: origin.URL + "/base/", Networks: []string{"192.0.2.0/24"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	if _, err = denied.Get(context.Background(), "pkg/file", nil); err == nil {
		t.Fatal("unauthorized destination dialed")
	}
	for _, p := range []string{"../escape", "x/../escape", "/absolute", "x%2f..%2fsecret", "x\\secret", "x?query"} {
		if _, err = e.Get(context.Background(), p, nil); err == nil {
			t.Fatalf("accepted ambiguous path %q", p)
		}
	}
}
func TestConfiguration(t *testing.T) {
	for _, cfg := range []Config{{URL: "https://example.com/"}, {URL: "http://example.com/", Networks: []string{"0.0.0.0/0"}}, {URL: "https://user:secret@example.com/", Networks: []string{"0.0.0.0/0"}}, {URL: "https://example.com/?secret=x", Networks: []string{"0.0.0.0/0"}}} {
		if _, err := New(cfg, ""); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestScopedPackageEncodingAndPinnedURL(t *testing.T) {
	var uri string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { uri = r.RequestURI; io.WriteString(w, "fixture") }))
	defer origin.Close()
	e, err := New(Config{URL: origin.URL + "/base/", Networks: []string{"127.0.0.1/32"}}, "", "127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r, err := e.GetPackage(context.Background(), "@scope/pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if !strings.Contains(strings.ToLower(uri), "%2f") {
		t.Fatal("scoped package separator was not encoded", uri)
	}
	for _, raw := range []string{origin.URL + "/outside/pkg.tgz", origin.URL + "/base/%2e%2e/escape", origin.URL + "/base/%252e%252e/escape", origin.URL + "/base/pkg.tgz?credential=private"} {
		if e.AllowsURL(raw) {
			t.Fatal("unapproved complete URL accepted", raw)
		}
		if _, err = e.GetURL(context.Background(), raw, nil); err == nil {
			t.Fatal("unapproved URL fetched")
		}
	}
	if !e.AllowsURL(origin.URL + "/base/@scope%2Fpkg/file.tgz") {
		t.Fatal("canonical encoded scope rejected")
	}
}

func TestOperatorNetworkCeilingAndRebinding(t *testing.T) {
	hits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; io.WriteString(w, "owned fixture") }))
	defer origin.Close()
	cfg := Config{URL: origin.URL + "/base/", Networks: []string{"0.0.0.0/0"}}
	denied, e := New(cfg, "")
	if e != nil {
		t.Fatal(e)
	}
	defer denied.Close()
	if _, e = denied.Get(context.Background(), "file", nil); e == nil {
		t.Fatal("tenant network authorization exceeded operator private-network ceiling")
	}
	approved, e := New(cfg, "", "127.0.0.1/32")
	if e != nil {
		t.Fatal(e)
	}
	defer approved.Close()
	// A pooled connection remains bound to its already approved IP. Force a new
	// dial here to test rebinding rather than racing connection-pool cleanup.
	approved.transport.DisableKeepAlives = true
	r, e := approved.Get(context.Background(), "file", nil)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	approved.Close()
	approved.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	if _, e = approved.Get(context.Background(), "file", nil); e == nil {
		t.Fatal("DNS rebinding escaped network ceiling")
	}
	if hits != 1 {
		t.Fatal("unexpected upstream request count")
	}
}
func FuzzUpstreamPath(f *testing.F) {
	for _, p := range []string{"package/file.jar", "../escape", "x%2f..", "x?query", "x\\file"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if SafePath(p) {
			u := url.URL{Scheme: "https", Host: "registry.invalid", Path: "/approved/" + p}
			parsed, e := url.Parse(u.String())
			if e != nil || parsed.Host != "registry.invalid" || !strings.HasPrefix(path.Clean(parsed.Path), "/approved/") || parsed.RawQuery != "" || parsed.Fragment != "" {
				t.Fatal("path escaped its authority")
			}
		}
	})
}

func TestConfiguredBasicAuthentication(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "fixture-user" || password != "fixture-password" {
			t.Error("configured Basic authentication mismatch")
		}
		io.WriteString(w, "fixture")
	}))
	defer origin.Close()
	endpoint, e := New(Config{URL: origin.URL + "/", Networks: []string{"127.0.0.1/32"}, Authentication: "basic"}, "fixture-user:fixture-password", "127.0.0.1/32")
	if e != nil {
		t.Fatal(e)
	}
	defer endpoint.Close()
	r, e := endpoint.Get(context.Background(), "file", nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
}
