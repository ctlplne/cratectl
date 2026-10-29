// SPDX-License-Identifier: BUSL-1.1
package consoleui

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestPackagedConsoleHasStrictScopeAndNoHTMLAssetFallback(t *testing.T) {
	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		Serve(w, httptest.NewRequest(method, path, nil))
		return w
	}
	page := get("GET", "/console/")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "cratectl") || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("console shell unavailable or cached")
	}
	policy := page.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "unsafe-inline") || !strings.Contains(policy, "connect-src 'self'") || page.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("unsafe console policy")
	}
	if page.Header().Get("Set-Cookie") != "" {
		t.Fatal("static shell set a session cookie")
	}
	for _, target := range []string{"/console/assets/", "/console/../store/schema.sql", "/console/assets/not-built.js", "/console/.private/admin.token"} {
		if w := get("GET", target); w.Code != 404 || strings.Contains(w.Body.String(), "<div id=\"root\"") {
			t.Fatal("asset path exposed data or silently returned HTML:", target, w.Code)
		}
	}
	asset := regexp.MustCompile(`src="(/console/assets/[^"]+\.js)"`).FindStringSubmatch(page.Body.String())
	if len(asset) != 2 {
		t.Fatal("missing packaged JS")
	}
	w := get("GET", asset[1])
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("asset MIME/cache contract")
	}
	if w = get("POST", "/console/"); w.Code != 405 {
		t.Fatal("static mutation accepted")
	}
	if w = get("HEAD", "/console/"); w.Code != 200 {
		t.Fatal("HEAD unavailable")
	}
}
