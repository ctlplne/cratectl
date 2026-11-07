// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestGoExportManagementRejectsAmbiguousRequestsBeforeDatabase(t *testing.T) {
	base := `{"repository":"owned","module":"go.cratectl.invalid/Owned/app","version":"v1.0.0","expected_source_revision":0,"lifetime_seconds":60}`
	for _, body := range []string{"", `{}`, base + `{}`, strings.Replace(base, `"repository":`, `"repository":"owned","repository":`, 1), strings.Replace(base, `"repository":`, `"Repository":`, 1), strings.Replace(base, `"repository":"owned"`, `"repository":null`, 1), strings.Replace(base, `"lifetime_seconds":60`, `"lifetime_seconds":0`, 1), strings.Replace(base, `"version":"v1.0.0"`, `"version":"v1.0"`, 1), strings.Repeat("x", 4097)} {
		r := httptest.NewRequest("POST", "/api/v1/go/exports", strings.NewReader(body))
		w := httptest.NewRecorder()
		if !new(Server).goExportManagement(w, r, store.Identity{Role: "admin"}, "go/exports") || w.Code != 400 {
			t.Fatal("ambiguous export reached database", w.Code)
		}
	}
	for _, query := range []string{"", "generation=0", "generation=01", "generation=1&generation=1", "generation=1&unknown=1", "generation=9223372036854775808"} {
		path := "go/exports/" + strings.Repeat("a", 64) + "/zip"
		r := httptest.NewRequest("GET", "/api/v1/"+path+"?"+query, nil)
		w := httptest.NewRecorder()
		if !new(Server).goExportManagement(w, r, store.Identity{Role: "admin"}, path) || w.Code != 400 {
			t.Fatal("ambiguous generation reached database", query, w.Code)
		}
	}
	for _, ranges := range [][]string{{"bytes=0-1,3-4"}, {"bytes=0-1", "bytes=3-4"}, {strings.Repeat("x", 1025)}} {
		path := "go/exports/" + strings.Repeat("a", 64) + "/zip"
		r := httptest.NewRequest("GET", "/api/v1/"+path+"?generation=1", nil)
		for _, v := range ranges {
			r.Header.Add("Range", v)
		}
		w := httptest.NewRecorder()
		if !new(Server).goExportManagement(w, r, store.Identity{Role: "admin"}, path) || w.Code != 400 {
			t.Fatal("unbounded range reached database", w.Code)
		}
	}
}

func TestGoExportManagementIsAdministratorScopedAndExact(t *testing.T) {
	for _, path := range []string{"go/exports", "go/exports/preview", "go/exports/" + strings.Repeat("a", 64), "go/exports/" + strings.Repeat("a", 64) + "/manifest"} {
		w := httptest.NewRecorder()
		if !new(Server).goExportManagement(w, httptest.NewRequest("GET", "/", nil), store.Identity{Role: "reader"}, path) || w.Code != 403 {
			t.Fatal("reader exposed export metadata", path, w.Code)
		}
	}
	for _, path := range []string{"go/exportsx", "go/exports/preview/unknown", "repositories/owned/go/exports", "go/exports/a/zip/extra"} {
		if new(Server).goExportManagement(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), store.Identity{}, path) {
			t.Fatal("unrelated route claimed", path)
		}
	}
	w := httptest.NewRecorder()
	if !new(Server).goExportManagement(w, httptest.NewRequest("GET", "/", nil), store.Identity{Role: "admin"}, "go/exports/preview") || w.Code != 405 || w.Header().Get("Allow") != "POST" {
		t.Fatal("preview method", w.Code)
	}
	w = httptest.NewRecorder()
	if !new(Server).goExportManagement(w, httptest.NewRequest("GET", "/", nil), store.Identity{Role: "admin"}, "go/exports/not-an-id") || w.Code != 400 {
		t.Fatal("malformed identity reached database", w.Code)
	}
}

func FuzzGoExportRequest(f *testing.F) {
	f.Add([]byte(`{"repository":"owned","module":"go.cratectl.invalid/owned","version":"v1.0.0","expected_source_revision":0,"lifetime_seconds":60}`))
	f.Add([]byte(`{"repository":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		var r store.GoExportRequest
		if decodeGoExport(raw, &r, "repository", "module", "version", "expected_source_revision", "lifetime_seconds") {
			canonical, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var second store.GoExportRequest
			if !decodeGoExport(canonical, &second, "repository", "module", "version", "expected_source_revision", "lifetime_seconds") || !reflect.DeepEqual(r, second) {
				t.Fatal("accepted unstable request")
			}
		}
	})
}
