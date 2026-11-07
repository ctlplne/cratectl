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

func exportSetRequestBody() string {
	return `{"entries":[{"repository":"owned","module":"go.cratectl.invalid/Owned/set","version":"v1.0.0","expected_source_revision":0},{"repository":"other","module":"go.cratectl.invalid/Owned/set","version":"v1.0.1","expected_source_revision":0}],"lifetime_seconds":60,"max_artifact_bytes":1073741824}`
}

func TestGoExportSetPreviewRejectsAmbiguityAndBudgetsBeforeDatabase(t *testing.T) {
	base := exportSetRequestBody()
	for _, scenario := range []string{"empty", "null", "duplicate-root", "alias-root", "unknown-root", "null-budget", "duplicate-member-field", "alias-member-field", "null-member-field", "unknown-member-field", "duplicate-coordinate", "zero-budget", "large-budget", "short-lifetime", "no-members", "wrong-shape", "null-member", "trailing", "large-body"} {
		t.Run(scenario, func(t *testing.T) {
			raw := base
			switch scenario {
			case "empty":
				raw = ""
			case "null":
				raw = "null"
			case "duplicate-root":
				raw = strings.Replace(raw, `"entries":`, `"entries":[],"entries":`, 1)
			case "alias-root":
				raw = strings.Replace(raw, `"entries":`, `"Entries":`, 1)
			case "unknown-root":
				raw = strings.Replace(raw, `"entries":`, `"unknown":true,"entries":`, 1)
			case "null-budget":
				raw = strings.Replace(raw, `"max_artifact_bytes":1073741824`, `"max_artifact_bytes":null`, 1)
			case "duplicate-member-field":
				raw = strings.Replace(raw, `"repository":`, `"repository":"owned","repository":`, 1)
			case "alias-member-field":
				raw = strings.Replace(raw, `"repository":`, `"Repository":`, 1)
			case "null-member-field":
				raw = strings.Replace(raw, `"repository":"owned"`, `"repository":null`, 1)
			case "unknown-member-field":
				raw = strings.Replace(raw, `"repository":`, `"unknown":true,"repository":`, 1)
			case "duplicate-coordinate":
				raw = strings.Replace(raw, `"version":"v1.0.1"`, `"version":"v1.0.0"`, 1)
			case "zero-budget":
				raw = strings.Replace(raw, `1073741824`, `0`, 1)
			case "large-budget":
				raw = strings.Replace(raw, `1073741824`, `68719476737`, 1)
			case "short-lifetime":
				raw = strings.Replace(raw, `"lifetime_seconds":60`, `"lifetime_seconds":59`, 1)
			case "no-members":
				raw = `{"entries":[],"lifetime_seconds":60,"max_artifact_bytes":1}`
			case "wrong-shape":
				raw = `{"entries":{},"lifetime_seconds":60,"max_artifact_bytes":1}`
			case "null-member":
				raw = `{"entries":[null],"lifetime_seconds":60,"max_artifact_bytes":1}`
			case "trailing":
				raw += "{}"
			case "large-body":
				raw = strings.Repeat(" ", store.MaxGoExportSetRequest+1)
			}
			request, ok := decodeGoExportSet([]byte(raw))
			if ok || len(request.Entries) != 0 {
				t.Fatal("invalid selection returned members", scenario)
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/v1/go/export-sets/preview", strings.NewReader(raw))
			if !new(Server).goExportSetManagement(w, r, store.Identity{Role: "admin"}, "go/export-sets/preview") || w.Code != 400 {
				t.Fatal("invalid selection reached database", scenario, w.Code)
			}
		})
	}
	request, ok := decodeGoExportSet([]byte(base))
	if !ok || len(request.Entries) != 2 || request.MaxArtifactBytes != 1<<30 {
		t.Fatal("valid selected order rejected")
	}
	pretty, _ := json.MarshalIndent(request, "", "  ")
	roundTrip, ok := decodeGoExportSet(pretty)
	if !ok || !reflect.DeepEqual(request, roundTrip) {
		t.Fatal("ordinary API whitespace changed selection")
	}
}

func TestGoExportSetPreviewMethodAuthorityAndRoute(t *testing.T) {
	for _, role := range []string{"reader", "writer", "worker", ""} {
		w := httptest.NewRecorder()
		if !new(Server).goExportSetManagement(w, httptest.NewRequest("POST", "/", strings.NewReader(exportSetRequestBody())), store.Identity{Role: role}, "go/export-sets/preview") || w.Code != 403 {
			t.Fatal("nonadministrator reached metadata", role, w.Code)
		}
	}
	for _, method := range []string{"GET", "HEAD", "PATCH", "DELETE", "PUT"} {
		w := httptest.NewRecorder()
		if !new(Server).goExportSetManagement(w, httptest.NewRequest(method, "/", nil), store.Identity{Role: "admin"}, "go/export-sets/preview") || w.Code != 405 || w.Header().Get("Allow") != "POST" {
			t.Fatal("incorrect preview method", method, w.Code)
		}
	}
	w := httptest.NewRecorder()
	if !new(Server).goExportSetManagement(w, httptest.NewRequest("POST", "/?unknown=1", strings.NewReader(exportSetRequestBody())), store.Identity{Role: "admin"}, "go/export-sets/preview") || w.Code != 400 {
		t.Fatal("query accepted")
	}
	for _, path := range []string{"go/export-sets", "go/export-sets/previewx", "go/export-sets/preview/extra", "go/exports/preview", "repositories/owned/go/export-sets/preview"} {
		if new(Server).goExportSetManagement(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), store.Identity{Role: "admin"}, path) {
			t.Fatal("unrelated route claimed", path)
		}
	}
}

func FuzzGoExportSetRequest(f *testing.F) {
	f.Add([]byte(exportSetRequestBody()))
	f.Add([]byte(`{"entries":null}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		request, ok := decodeGoExportSet(raw)
		if !ok {
			if len(request.Entries) != 0 {
				t.Fatal("invalid request retained members")
			}
			return
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		second, ok := decodeGoExportSet(encoded)
		if !ok || !reflect.DeepEqual(request, second) || request.Validate() != nil || len(encoded) > store.MaxGoExportSetRequest {
			t.Fatal("unstable selection")
		}
	})
}
