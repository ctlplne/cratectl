//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIndependentHoldCasesPreserveOtherProtection(t *testing.T) {
	s, _, token, _ := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "case-holds", "format": "oci"}, "case-holds-repository"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	digest := lifecyclePublish(t, s, token, "case-holds", "independent reviews")
	path := "app/manifests/sha256:" + digest
	base := "/api/v1/repositories/case-holds/artifacts/holds/"
	input := map[string]any{"path": path, "digest": digest, "action": "hold", "expected_revision": 0, "reason": "Independent preservation review"}
	for _, name := range []string{"review-a", "review-b"} {
		if w := api("PUT", base+name, input, "place-case-"+name); w.Code != 200 {
			t.Fatal("cannot place independent hold", name, w.Code, w.Body.String())
		}
	}
	input["action"], input["expected_revision"] = "release_hold", 1
	if w := api("PUT", base+"review-a", input, "release-case-review-a"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("DELETE", "/v2/case-holds/"+path, nil, ""); w.Code != 409 {
		t.Fatal("releasing case A removed case B protection", w.Code, w.Body.String())
	}
	state := api("GET", "/api/v1/repositories/case-holds/artifacts/lifecycle?path="+url.QueryEscape(path), nil, "")
	var current struct{ Held bool }
	if state.Code != 200 || json.Unmarshal(state.Body.Bytes(), &current) != nil || !current.Held {
		t.Fatal("aggregate hold missing", state.Code, state.Body.String())
	}
	if w := api("PUT", base+"review-b", input, "release-case-review-b"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("DELETE", "/v2/case-holds/"+path, nil, ""); w.Code != 202 {
		t.Fatal("last case release did not permit native deletion", w.Code, w.Body.String())
	}
}

func TestHoldCaseScopesRetainedRecoveryAndCurrentAuthority(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	ctx := context.Background()
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "case-holds", "format": "oci"}, "case-scope-repository"); w.Code != 201 {
		t.Fatal(w.Code)
	}
	digest := lifecyclePublish(t, s, token, "case-holds", "case authority recovery")
	path := "app/manifests/sha256:" + digest
	base := "/api/v1/repositories/case-holds/artifacts/holds/"
	in := map[string]any{"path": path, "digest": digest, "action": "hold", "expected_revision": 0, "reason": "Original independent review"}
	dry := map[string]any{}
	for k, v := range in {
		dry[k] = v
	}
	dry["dry_run"] = true
	if w := api("PUT", base+"a", dry, ""); w.Code != 200 {
		t.Fatal("dry-run", w.Code, w.Body.String())
	}
	if w := api("GET", "/api/v1/hold-cases?state=all", nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("preview persisted a case", w.Code, w.Body.String())
	}
	for _, id := range []string{"a", "b", "c"} {
		if w := api("PUT", base+id, in, "place-scoped-case-"+id); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var first struct {
		Items          []store.HoldCase
		Next, Previous string
	}
	w := api("GET", "/api/v1/hold-cases?state=all&limit=1", nil, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Items) != 1 || first.Next == "" || strings.Contains(first.Next, path) {
		t.Fatal("encrypted case page", w.Code, w.Body.String())
	}
	var second struct {
		Items          []store.HoldCase
		Next, Previous string
	}
	w = api("GET", "/api/v1/hold-cases?state=all&limit=1&cursor="+url.QueryEscape(first.Next), nil, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || len(second.Items) != 1 || second.Items[0].CaseID == first.Items[0].CaseID || second.Previous == "" {
		t.Fatal("forward case page", w.Code, w.Body.String())
	}
	w = api("GET", "/api/v1/hold-cases?state=all&limit=1&cursor="+url.QueryEscape(second.Previous), nil, "")
	var back struct{ Items []store.HoldCase }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &back) != nil || len(back.Items) != 1 || back.Items[0].CaseID != first.Items[0].CaseID {
		t.Fatal("reverse case page", w.Code, w.Body.String())
	}
	for _, query := range []string{"state=active&cursor=" + url.QueryEscape(first.Next), "state=all&case_id=a&cursor=" + url.QueryEscape(first.Next), "state=all&repository=case-holds&cursor=" + url.QueryEscape(first.Next), "state=all&q=Review&cursor=" + url.QueryEscape(first.Next), "limit=101", "limit=0", "limit=oops", "limit=1&limit=2", "q=%ff", "path=bad", "state=unknown", "case_id=legacy", "unknown=x"} {
		if w := api("GET", "/api/v1/hold-cases?"+query, nil, ""); w.Code != 400 {
			t.Fatal("invalid case query", query, w.Code)
		}
	}
	history := base + "a/history?" + url.Values{"path": {path}, "cursor": {first.Next}}.Encode()
	if w := api("GET", history, nil, ""); w.Code != 400 {
		t.Fatal("inventory cursor crossed case history", w.Code)
	}
	for _, role := range []string{"reader", "writer", "admin"} {
		credential, _ := crypt.Token()
		if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, role, role, credential, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		other := lifecycleHTTP(t, s, credential)
		if role == "admin" {
			if w := other("GET", "/api/v1/hold-cases?state=all&cursor="+url.QueryEscape(first.Next), nil, ""); w.Code != 400 {
				t.Fatal("cursor crossed current credential", w.Code)
			}
		} else {
			for _, endpoint := range []string{"/api/v1/hold-cases", base + "a?" + url.Values{"path": {path}}.Encode(), base + "a/history?" + url.Values{"path": {path}}.Encode()} {
				if w := other("GET", endpoint, nil, ""); w.Code != 403 {
					t.Fatal("nonadmin case read", role, w.Code)
				}
			}
			if w := other("PUT", base+"a", in, "place-scoped-case-a"); w.Code != 403 {
				t.Fatal("nonadmin case replay", role, w.Code)
			}
		}
	}
	if w := api("PUT", base+"a", in, "place-scoped-case-a"); w.Code != 200 || w.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("exact case replay", w.Code, w.Body.String())
	}
	if w := api("PUT", "/api/v1/repositories/case-holds/state", map[string]any{"action": "remove", "expected_revision": 0, "reason": "Retain during review"}, "case-remove-repository"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if e := store.Revoke(ctx, d.OwnerDSN, token); e != nil {
		t.Fatal(e)
	}
	if w := api("PUT", base+"a", in, "place-scoped-case-a"); w.Code != 401 {
		t.Fatal("revoked actor replayed hold", w.Code)
	}
	recovery, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "recovery", "admin", recovery, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	recoverAPI := lifecycleHTTP(t, s, recovery)
	in["action"], in["expected_revision"], in["reason"] = "release_hold", 1, "Current administrator completes case A"
	w = recoverAPI("PUT", base+"a", in, "recover-case-a-release")
	var result store.HoldCasePreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Current.Held || !result.Case.Released {
		t.Fatal("retained case recovery removed other holds", w.Code, w.Body.String())
	}
	if w := recoverAPI("GET", "/v2/case-holds/"+path, nil, ""); w.Code != 404 {
		t.Fatal("case recovery bypassed repository removal", w.Code)
	}
	if w := recoverAPI("GET", base+"a/history?"+url.Values{"path": {path}}.Encode(), nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Current administrator completes case A") {
		t.Fatal("independent recovery receipt missing", w.Code, w.Body.String())
	}
}
