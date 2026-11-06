// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"ctlplne.dev/cratectl/internal/store"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoNativeErrorsRemainPlainTextAndSuccessfulBytesUnchanged(t *testing.T) {
	w := httptest.NewRecorder()
	response := &goProtocolResponse{ResponseWriter: w}
	w.Header().Set("Content-Length", "123")
	fail(response, 403, "policy_denied", "Ask the owner to review these exact bytes.")
	if w.Code != 403 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || w.Header().Get("Content-Length") != "" || w.Body.String() != "policy_denied: Ask the owner to review these exact bytes.\n" {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
	ok := httptest.NewRecorder()
	r := &goProtocolResponse{ResponseWriter: ok}
	body := []byte{0, 1, 2, 255}
	r.Header().Set("Content-Type", "application/zip")
	r.WriteHeader(http.StatusPartialContent)
	if n, e := r.Write(body); e != nil || n != len(body) || !bytes.Equal(ok.Body.Bytes(), body) || ok.Code != 206 || ok.Header().Get("Content-Type") != "application/zip" {
		t.Fatal(ok.Code, n, e)
	}
}

func TestGoModuleCacheRefusalKeepsNativeRetryAndPlainTextContract(t *testing.T) {
	w := httptest.NewRecorder()
	respondErr(&goProtocolResponse{ResponseWriter: w}, store.ErrGoModuleCacheExpired)
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !bytes.HasPrefix(w.Body.Bytes(), []byte("go_module_cache_expired: ")) {
		t.Fatal("cache revalidation error lost native retry/plain-text behavior", w.Code, w.Header())
	}
}

func TestGoModuleSourceChangeRefusesClientFallback(t *testing.T) {
	w := httptest.NewRecorder()
	respondErr(&goProtocolResponse{ResponseWriter: w}, store.ErrSourceChanged)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !bytes.HasPrefix(w.Body.Bytes(), []byte("source_configuration_changed: ")) {
		t.Fatal("changed source lost the native revalidation refusal", w.Code, w.Header())
	}
}
func TestGoLatestChoosesReleasePrereleaseThenChronologicalPseudoVersion(t *testing.T) {
	for _, tc := range []struct {
		versions []string
		want     string
	}{
		{nil, ""}, {[]string{"v1.0.0", "v1.1.0-beta"}, "v1.0.0"}, {[]string{"v1.0.0-beta", "v1.1.0-beta"}, "v1.1.0-beta"},
		{[]string{"v0.0.0-20261104010203-0123456789ab", "v1.0.1-0.20251004010203-0123456789ab"}, "v0.0.0-20261104010203-0123456789ab"},
	} {
		if got := latestGoVersion(tc.versions); got != tc.want {
			t.Errorf("%v: %s", tc.versions, got)
		}
	}
}

func TestGoLatestKeepsPolicyHiddenModulesDistinctFromAbsence(t *testing.T) {
	for _, tc := range []struct {
		view store.GoModuleVersionView
		want string
		err  error
	}{
		{store.GoModuleVersionView{}, "", store.ErrNotFound},
		{store.GoModuleVersionView{Known: true}, "", store.ErrDenied},
		{store.GoModuleVersionView{Known: true, Versions: []string{"v1.0.0", "v1.1.0-beta"}}, "v1.0.0", nil},
	} {
		got, e := latestGoSelection(tc.view)
		if got != tc.want || !errors.Is(e, tc.err) {
			t.Fatal("latest selection authorized fallback for a known blocked module", got, e)
		}
	}
}
func TestGoNativeRejectsAliasesAndInvalidMutationBeforeStoreUse(t *testing.T) {
	s := New(nil, nil, "")
	for _, tc := range []struct {
		path, method string
		status       int
	}{
		{"go.cratectl.invalid/app/@v/latest", "GET", 400}, {"go.cratectl.invalid/app/@v/v1.0.0.mod", "PUT", 405}, {"go.cratectl.invalid/app/@v/v1.0.0.zip", "PUT", 400},
	} {
		w := httptest.NewRecorder()
		s.goModule(w, httptest.NewRequest(tc.method, "/go/owned/"+tc.path, nil), store.Identity{}, store.Repository{Name: "owned", Format: "go", Mode: "hosted"}, tc.path)
		if w.Code != tc.status {
			t.Fatal(tc, w.Code)
		}
	}
}
