//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestHoldMatterGroupsReferencesAcrossRepositories(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	input := map[string]any{"expected_revision": 0, "title": "Owned cross-repository investigation", "reason": "Preserve independently reviewed package references", "state": "open"}
	if w := api("PUT", "/api/v1/hold-matters/incident-review", input, "create-owned-hold-matter"); w.Code != 200 {
		t.Fatal("tenant-wide matter is unavailable", w.Code, w.Body.String())
	}
	ctx := context.Background()
	workerToken, _ := crypt.Token()
	approverToken, _ := crypt.Token()
	for _, credential := range []struct{ actor, role, token string }{{"matter-worker", "worker", workerToken}, {"matter-approver", "admin", approverToken}} {
		if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, credential.actor, credential.role, credential.token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	worker, e := s.DB.AuthenticateWorker(ctx, workerToken)
	if e != nil {
		t.Fatal(e)
	}
	base := "/api/v1/hold-matters/incident-review"
	selectors := []store.MatterSelector{}
	paths := map[string]string{}
	for _, repo := range []string{"matter-a", "matter-b"} {
		if w := api("POST", "/api/v1/repositories", map[string]string{"name": repo, "format": "oci"}, "create-"+repo); w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
		digest := lifecyclePublish(t, s, token, repo, "Owned matter bytes "+repo)
		path := "app/manifests/sha256:" + digest
		paths[repo] = path
		selectors = append(selectors, store.MatterSelector{Repository: repo, Path: path})
	}
	preview := func(action string) store.MatterPlan {
		t.Helper()
		w := api("POST", base+"/operations/preview", store.MatterPreviewRequest{Action: action, Reason: "Owned cross-reference preservation review", Targets: selectors}, "")
		var p store.MatterPlan
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.TargetCount != 2 {
			t.Fatal("complete preview", w.Code, w.Body.String())
		}
		return p
	}
	admit := func(plan store.MatterPlan, key string) store.MatterOperation {
		t.Helper()
		w := api("POST", base+"/operations", plan, key)
		var value struct{ Operation store.MatterOperation }
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &value) != nil {
			t.Fatal("immutable operation", w.Code, w.Body.String())
		}
		return value.Operation
	}
	drain := func(id string) {
		t.Helper()
		for n := 0; n < 3; n++ {
			j, e := s.DB.ClaimJob(ctx, worker, "maintenance", "matter-fixture", time.Minute)
			if e != nil || j.ID() != id {
				t.Fatal("claim exact operation", j, e)
			}
			state, e := s.DB.StepHoldMatter(ctx, worker, j)
			if e != nil {
				t.Fatal(e)
			}
			if state == "succeeded" {
				return
			}
		}
		t.Fatal("matter operation did not finish")
	}
	hold := admit(preview("hold"), "admit-owned-matter-placement")
	if hold.State != "approved" || hold.Job == "" {
		t.Fatal(hold)
	}
	drain(hold.Job)
	for repo, path := range paths {
		if w := api("DELETE", "/v2/"+repo+"/"+path, nil, ""); w.Code != 409 {
			t.Fatal("matter did not protect exact reference", repo, w.Code, w.Body.String())
		}
	}
	page := api("GET", base+"/members?state=active", nil, "")
	var members struct{ Items []store.MatterMemberRecord }
	if page.Code != 200 || json.Unmarshal(page.Body.Bytes(), &members) != nil || len(members.Items) != 2 {
		t.Fatal("cross-reference membership", page.Code, page.Body.String())
	}
	var first, second struct {
		Items          []store.MatterMemberRecord
		Next, Previous string
	}
	page = api("GET", base+"/members?state=active&limit=1", nil, "")
	if page.Code != 200 || json.Unmarshal(page.Body.Bytes(), &first) != nil || len(first.Items) != 1 || first.Next == "" {
		t.Fatal("bounded member cursor", page.Code, page.Body.String())
	}
	page = api("GET", base+"/members?state=active&limit=1&cursor="+url.QueryEscape(first.Next), nil, "")
	if page.Code != 200 || json.Unmarshal(page.Body.Bytes(), &second) != nil || len(second.Items) != 1 || first.Items[0].Repository == second.Items[0].Repository || second.Previous == "" {
		t.Fatal("forward member cursor", page.Code, page.Body.String())
	}
	page = api("GET", base+"/members?state=active&limit=1&cursor="+url.QueryEscape(second.Previous), nil, "")
	var back struct{ Items []store.MatterMemberRecord }
	if page.Code != 200 || json.Unmarshal(page.Body.Bytes(), &back) != nil || len(back.Items) != 1 || back.Items[0].Repository != first.Items[0].Repository {
		t.Fatal("reverse member cursor", page.Code, page.Body.String())
	}
	for _, suffix := range []string{"/members?state=all&cursor=", "/members?state=active&repository=matter-a&cursor=", "/members?state=active&q=owned&cursor=", "/history?cursor=", "/operations?cursor=", "/operations/" + strconv.FormatInt(hold.Sequence, 10) + "/items?cursor="} {
		if w := api("GET", base+suffix+url.QueryEscape(first.Next), nil, ""); w.Code != 400 {
			t.Fatal("cursor crossed scope", suffix, w.Code)
		}
	}
	other := lifecycleHTTP(t, s, approverToken)
	if w := other("GET", base+"/members?state=active&cursor="+url.QueryEscape(first.Next), nil, ""); w.Code != 400 {
		t.Fatal("cursor crossed credential", w.Code)
	}
	release := admit(preview("release_hold"), "request-owned-matter-release")
	if release.State != "awaiting_approval" || release.Job != "" {
		t.Fatal("release executed without approval", release)
	}
	review := store.MatterApprovalRequest{ExpectedRevision: release.Revision, Digest: release.Plan.Digest, Reason: "Independent administrator approves exact release manifest"}
	endpoint := base + "/operations/" + strconv.FormatInt(release.Sequence, 10) + "/approve"
	if w := api("POST", endpoint, review, "self-approve-matter-release"); w.Code != 403 {
		t.Fatal("requester approved their own release", w.Code, w.Body.String())
	}
	approve := lifecycleHTTP(t, s, approverToken)
	w := approve("POST", endpoint, review, "independent-matter-release")
	var approved struct{ Operation store.MatterOperation }
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &approved) != nil || approved.Operation.Job == "" {
		t.Fatal("distinct approval", w.Code, w.Body.String())
	}
	drain(approved.Operation.Job)
	for repo, path := range paths {
		if w := api("DELETE", "/v2/"+repo+"/"+path, nil, ""); w.Code != 202 {
			t.Fatal("approved matter release did not permit deletion", repo, w.Code, w.Body.String())
		}
		if w := api("GET", "/api/v1/repositories/"+repo+"/artifacts/lifecycle?"+url.Values{"path": {path}}.Encode(), nil, ""); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
}

func TestHoldMatterStrictHTTPInputsAndLiteralSearch(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	base := "/api/v1/hold-matters"
	for n, title := range []string{"Literal %_ [a-z] investigation", "Plain investigation"} {
		input := map[string]any{"expected_revision": 0, "title": title, "state": "open", "reason": "Owned literal search"}
		if w := api("PUT", base+"/review-"+strconv.Itoa(n), input, "create-literal-matter-"+strconv.Itoa(n)); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := api("GET", base+"?q="+url.QueryEscape("%_ [a-z]"), nil, "")
	var page struct{ Items []store.HoldMatter }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].Name != "review-0" {
		t.Fatal("search interpreted punctuation", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"?limit=101", "?limit=0", "?limit=oops", "?limit=1&limit=2", "?q=%ff", "?unknown=x", "/review-0/members?state=bogus", "/review-0/operations/01", "/review-0/operations/0", "/review-0?limit=1"} {
		if w := api("GET", base+suffix, nil, ""); w.Code != 400 {
			t.Fatal("invalid matter query", suffix, w.Code, w.Body.String())
		}
	}
	for _, body := range []string{
		`{"title":"No explicit revision","state":"open","reason":"Owned"}`,
		`{"expected_revision":0,"title":"Duplicate","title":"Other","state":"open","reason":"Owned"}`,
		`{"expected_revision":0,"title":"Unknown","state":"open","reason":"Owned","unknown":true}`,
		`{"expected_revision":null,"title":"Null revision","state":"open","reason":"Owned"}`,
		`{"expected_revision":0,"title":"Nested","state":"open","reason":"Owned"} {}`,
	} {
		r := httptest.NewRequest("PUT", base+"/bad-input", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", "strict-matter-input")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("malformed matter body", w.Code, w.Body.String())
		}
	}
	for _, role := range []string{"reader", "writer"} {
		credential, _ := crypt.Token()
		if e := store.Provision(context.Background(), d.OwnerDSN, admin.Tenant, "matter-"+role, role, credential, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		other := lifecycleHTTP(t, s, credential)
		for _, suffix := range []string{"", "/review-0", "/review-0/members", "/review-0/operations", "/review-0/history"} {
			if w := other("GET", base+suffix, nil, ""); w.Code != 403 {
				t.Fatal("nonadmin matter read", role, suffix, w.Code)
			}
		}
	}
}
