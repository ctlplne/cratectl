// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestRetentionJSONRequiresExplicitProtectionAndRejectsAmbiguity(t *testing.T) {
	good := `{"expected_revision":0,"min_age_seconds":60,"keep_last":1,"protect_tagged":true,"enabled":true,"reason":"Retain current versions"}`
	for _, body := range []string{strings.Replace(good, `"protect_tagged":true,`, "", 1), strings.Replace(good, `"protect_tagged":true`, `"protect_tagged":null`, 1), strings.Replace(good, `"expected_revision":0`, `"expected_revision":0,"expected_revision":1`, 1), strings.Replace(good, `"keep_last":1`, `"keep_last":1,"unknown":1`, 1), good + good, strings.Replace(good, `"enabled":true`, `"enabled":"true"`, 1), "null", string([]byte{'{', '"', 0xff, '"', ':', '0', '}'}), strings.Repeat(" ", 16385)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PUT", "/", strings.NewReader(body))
		var input store.RetentionPolicyRequest
		if _, ok := readRetentionBody(w, r, &input, "expected_revision", "min_age_seconds", "keep_last", "protect_tagged", "enabled", "reason"); ok {
			t.Fatal("ambiguous policy accepted", body)
		}
	}
	w := httptest.NewRecorder()
	var input store.RetentionPolicyRequest
	if _, ok := readRetentionBody(w, httptest.NewRequest("PUT", "/", strings.NewReader(good)), &input, "expected_revision", "min_age_seconds", "keep_last", "protect_tagged", "enabled", "reason"); !ok || input.RetentionSettings.Validate() != nil {
		t.Fatal(w.Body.String())
	}
}
func FuzzRetentionJSONBounded(f *testing.F) {
	for _, s := range []string{`{}`, `null`, `{"expected_revision":1,"reason":"owned","dry_run":true}`, `{"reason":"x","reason":"y"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var input store.RetentionRequest
		w := httptest.NewRecorder()
		readRetentionBody(w, httptest.NewRequest("POST", "/", strings.NewReader(s)), &input, "expected_revision", "reason")
	})
}

func TestRetentionMethodRejectionAdvertisesSupportedOperations(t *testing.T) {
	for path, want := range map[string]string{"repositories/containers/retention-policies/monthly": "GET, PUT", "repositories/containers/retention-policies/monthly/runs": "GET, POST", "maintenance/retention-runs/1:retention-example": "GET"} {
		w := httptest.NewRecorder()
		s := &Server{}
		if !s.retentionManagement(w, httptest.NewRequest("DELETE", "/api/v1/"+path, nil), store.Identity{Role: "admin"}, path) || w.Code != 405 || w.Header().Get("Allow") != want {
			t.Fatal(path, w.Code, w.Header().Get("Allow"))
		}
	}
}
