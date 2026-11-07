// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestGoRequirementCreationRejectsMalformedInputAndIdempotencyBeforeDatabase(t *testing.T) {
	for _, scenario := range []struct{ body, query, key string }{
		{requirementPreviewBody(), "", ""}, {"null", "", "owned"}, {"{}", "", "owned"},
		{requirementPreviewBody(), "?extra=1", "owned"}, {requirementPreviewBody() + "{}", "", "owned"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/"+scenario.query, strings.NewReader(scenario.body))
		if scenario.key != "" {
			r.Header.Set("Idempotency-Key", scenario.key)
		}
		if !new(Server).goExportSetManagement(w, r, store.Identity{Role: "admin"}, "go/export-sets/requirements") || w.Code != 400 {
			t.Fatal("invalid graph creation reached database", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(requirementPreviewBody()))
	r.Header.Add("Idempotency-Key", "owned-a")
	r.Header.Add("Idempotency-Key", "owned-b")
	w := httptest.NewRecorder()
	new(Server).goExportSetManagement(w, r, store.Identity{Role: "admin"}, "go/export-sets/requirements")
	if w.Code != 400 {
		t.Fatal("ambiguous mutation key reached database")
	}
}

func TestGoRequirementMetadataRoutesRejectAmbiguousIndicesQueriesAndMethods(t *testing.T) {
	base := "go/export-sets/requirements/" + strings.Repeat("a", 64)
	for _, suffix := range []string{"/inputs/00/mod", "/inputs/-1/mod", "/inputs/1024/mod", "/inputs/0/zip", "/inputs/0/mod/extra", "/main/extra", "/unknown"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?generation=1", nil)
		new(Server).goExportSetManagement(w, r, store.Identity{Role: "admin"}, base+suffix)
		if w.Code != 400 {
			t.Fatal("ambiguous graph object reached database", suffix, w.Code)
		}
	}
	for _, query := range []string{"", "?generation=0", "?generation=1&generation=2", "?generation=1&extra=1"} {
		w := httptest.NewRecorder()
		new(Server).goExportSetManagement(w, httptest.NewRequest("GET", "/"+query, nil), store.Identity{Role: "admin"}, base+"/main")
		if w.Code != 400 {
			t.Fatal("ambiguous generation reached database", query, w.Code)
		}
	}
	for _, path := range []string{"go/export-sets/requirements", base, base + "/main"} {
		w := httptest.NewRecorder()
		new(Server).goExportSetManagement(w, httptest.NewRequest("DELETE", "/", nil), store.Identity{Role: "admin"}, path)
		if w.Code != 405 {
			t.Fatal("graph object method guard changed", path, w.Code)
		}
		w = httptest.NewRecorder()
		new(Server).goExportSetManagement(w, httptest.NewRequest("GET", "/", nil), store.Identity{Role: "reader"}, path)
		if w.Code != 403 {
			t.Fatal("nonadmin graph metadata route reached database", path, w.Code)
		}
	}
}
