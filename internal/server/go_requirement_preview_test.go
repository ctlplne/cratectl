// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

func requirementPreviewBody() string {
	raw, _ := json.Marshal(goRequirementRequest{Repository: "owned", MainGoMod: "module owned/main\ngo 1.26.0\nrequire example.invalid/a v1.0.0\n",
		LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20})
	return string(raw)
}

func TestGoRequirementPreviewRejectsMalformedRequestsBeforeDatabase(t *testing.T) {
	base := requirementPreviewBody()
	if _, valid := decodeGoRequirementRequest([]byte(base)); !valid {
		t.Fatal("valid owned request shape refused")
	}
	for _, body := range []string{"", "null", base + "{}", strings.Repeat(" ", maxGoRequirementRequest+1),
		strings.Replace(base, `"repository":"owned"`, `"repository":"../outside"`, 1),
		strings.Replace(base, `"repository":`, `"Repository":`, 1),
		strings.Replace(base, `"repository":`, `"repository":"owned","repository":`, 1),
		strings.Replace(base, `"repository":`, `"credential":"owned-synthetic-value","repository":`, 1),
		strings.Replace(base, `"main_go_mod":`, `"MainGoMod":`, 1),
		strings.Replace(base, `"main_go_mod":`, `"main_go_mod":null,"original":`, 1),
		strings.Replace(base, `"expected_source_revision":0`, `"expected_source_revision":-1`, 1),
		strings.Replace(base, `"lifetime_seconds":60`, `"lifetime_seconds":59`, 1),
		strings.Replace(base, `"max_artifact_bytes":1048576`, `"max_artifact_bytes":0`, 1)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/go/export-sets/requirements/preview", strings.NewReader(body))
		if !new(Server).goExportSetManagement(w, r, store.Identity{Role: "admin"}, "go/export-sets/requirements/preview") || w.Code != 400 {
			t.Fatal("malformed dependency request reached database", w.Code)
		}
		if strings.Contains(w.Body.String(), `"manifest":`) || strings.Contains(w.Body.String(), `"examined_inputs":`) {
			t.Fatal("malformed request returned a partial graph")
		}
	}
	input := goRequirementRequest{Repository: "owned", MainGoMod: strings.Repeat("x", gomodule.MaxGoMod+1), LifetimeSeconds: 60, MaxArtifactBytes: 1}
	raw, _ := json.Marshal(input)
	if _, valid := decodeGoRequirementRequest(raw); valid {
		t.Fatal("oversized original go.mod admitted")
	}
}

func TestGoRequirementPreviewEnforcesRoleMethodAndQueryBeforeInput(t *testing.T) {
	for _, scenario := range []struct {
		role, method, query string
		status              int
	}{{"reader", "POST", "", 403}, {"admin", "GET", "", 405}, {"admin", "POST", "?unexpected=1", 400}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(scenario.method, "/api/v1/go/export-sets/requirements/preview"+scenario.query, strings.NewReader(requirementPreviewBody()))
		if !new(Server).goExportSetManagement(w, r, store.Identity{Role: scenario.role}, "go/export-sets/requirements/preview") || w.Code != scenario.status {
			t.Fatal("dependency preview admission guard changed", scenario, w.Code)
		}
	}
}

func TestGoRequirementPreviewExplainsEmptyProjectWithoutDatabaseAdmission(t *testing.T) {
	input := goRequirementRequest{Repository: "owned", MainGoMod: "module owned/main\ngo 1.27.0\n", LifetimeSeconds: 60, MaxArtifactBytes: 1}
	raw, _ := json.Marshal(input)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/go/export-sets/requirements/preview", strings.NewReader(string(raw)))
	if !new(Server).goExportSetManagement(w, r, store.Identity{Role: "admin"}, "go/export-sets/requirements/preview") || w.Code != 400 ||
		!strings.Contains(w.Body.String(), `"code":"empty_go_requirement_selection"`) || strings.Contains(w.Body.String(), `"selection":`) {
		t.Fatal("empty project reached the database or returned unclear/partial output", w.Code, w.Body.String())
	}
}
