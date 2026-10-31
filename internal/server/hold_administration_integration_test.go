//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHoldAdministrationPagingScopesRevocationAndInput(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	ctx := context.Background()
	api := lifecycleHTTP(t, s, token)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "holds", "format": "oci"}, "paging-hold-repository"); w.Code != 201 {
		t.Fatal(w.Code)
	}
	for n := 0; n < 3; n++ {
		digest := lifecyclePublish(t, s, token, "holds", fmt.Sprintf("owned-%d", n))
		in := map[string]any{"path": "app/manifests/sha256:" + digest, "digest": digest, "action": "hold", "expected_revision": 0, "reason": fmt.Sprintf("primary private hold %d", n)}
		if w := api("PUT", "/api/v1/repositories/holds/artifacts/lifecycle", in, fmt.Sprintf("paging-hold-%d", n)); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	type row struct{ Path, Digest, Status, HoldReason string }
	type page struct {
		Items          []row
		Next, Previous string
	}
	first := api("GET", "/api/v1/holds?state=all&limit=1", nil, "")
	var a page
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &a) != nil || len(a.Items) != 1 || a.Next == "" {
		t.Fatal("first encrypted page", first.Code, first.Body.String())
	}
	if strings.Contains(a.Next, a.Items[0].Path) || strings.Contains(a.Next, admin.Tenant) {
		t.Fatal("continuation exposed plaintext position or tenant")
	}
	next := api("GET", "/api/v1/holds?state=all&limit=1&cursor="+url.QueryEscape(a.Next), nil, "")
	var b page
	if next.Code != 200 || json.Unmarshal(next.Body.Bytes(), &b) != nil || len(b.Items) != 1 || b.Previous == "" || b.Items[0].Path <= a.Items[0].Path {
		t.Fatal("forward continuation", next.Code, next.Body.String())
	}
	back := api("GET", "/api/v1/holds?state=all&limit=1&cursor="+url.QueryEscape(b.Previous), nil, "")
	var earlier page
	if back.Code != 200 || json.Unmarshal(back.Body.Bytes(), &earlier) != nil || len(earlier.Items) != 1 || earlier.Items[0].Path != a.Items[0].Path {
		t.Fatal("reverse continuation", back.Code)
	}
	for _, q := range []string{"state=active&cursor=" + url.QueryEscape(a.Next), "state=all&q=different&cursor=" + url.QueryEscape(a.Next), "state=all&repository=holds&cursor=" + url.QueryEscape(a.Next), "limit=0", "limit=101", "limit=oops", "limit=1&limit=2", "state=missing", "repository=Upper", "q=%ff", "unknown=x"} {
		if w := api("GET", "/api/v1/holds?"+q, nil, ""); w.Code != 400 {
			t.Fatal("invalid or substituted hold query", q, w.Code)
		}
	}
	tampered := []byte(a.Next)
	if tampered[5] == 'A' {
		tampered[5] = 'B'
	} else {
		tampered[5] = 'A'
	}
	if w := api("GET", "/api/v1/holds?state=all&limit=1&cursor="+url.QueryEscape(string(tampered)), nil, ""); w.Code != 400 {
		t.Fatal("tampered cursor accepted", w.Code)
	}
	history := "/api/v1/repositories/holds/artifacts/lifecycle/history?path=" + url.QueryEscape(a.Items[0].Path)
	if w := api("GET", history+"&cursor="+url.QueryEscape(a.Next), nil, ""); w.Code != 400 {
		t.Fatal("inventory cursor crossed history endpoint", w.Code)
	}
	for _, method := range []string{"PUT", "POST", "DELETE"} {
		if w := api(method, "/api/v1/holds", nil, ""); w.Code != 405 || w.Header().Get("Allow") != "GET" {
			t.Fatal("hold inventory method accepted", method, w.Code)
		}
	}
	for _, role := range []string{"reader", "writer", "admin"} {
		credential, e := crypt.Token()
		if e != nil {
			t.Fatal(e)
		}
		actor := role
		if role == "admin" {
			actor = admin.Actor
		}
		if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, actor, role, credential, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		other := lifecycleHTTP(t, s, credential)
		if role == "admin" {
			if w := other("GET", "/api/v1/holds?state=all&limit=1&cursor="+url.QueryEscape(a.Next), nil, ""); w.Code != 400 {
				t.Fatal("cursor crossed credential", w.Code)
			}
		} else {
			for _, path := range []string{"/api/v1/holds", history} {
				if w := other("GET", path, nil, ""); w.Code != 403 {
					t.Fatal("non-administrator read hold evidence", role, w.Code)
				}
			}
		}
	}
	otherToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, d.OwnerDSN, "other-hold-team", admin.Actor, "admin", otherToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	other := lifecycleHTTP(t, s, otherToken)
	if w := other("POST", "/api/v1/repositories", map[string]string{"name": "holds", "format": "oci"}, "other-hold-repository"); w.Code != 201 {
		t.Fatal(w.Code)
	}
	digest := lifecyclePublish(t, s, otherToken, "holds", "owned-0")
	in := map[string]any{"path": "app/manifests/sha256:" + digest, "digest": digest, "action": "hold", "expected_revision": 0, "reason": "other tenant private evidence"}
	if w := other("PUT", "/api/v1/repositories/holds/artifacts/lifecycle", in, "other-hold-change"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := api("GET", "/api/v1/holds?state=all", nil, ""); w.Code != 200 || strings.Contains(w.Body.String(), "other tenant private evidence") {
		t.Fatal("tenant inventory collision leaked", w.Code)
	}
	if w := other("GET", "/api/v1/holds?state=all&limit=1&cursor="+url.QueryEscape(a.Next), nil, ""); w.Code != 400 {
		t.Fatal("cursor crossed tenant", w.Code)
	}
	if e = store.Revoke(ctx, d.OwnerDSN, token); e != nil {
		t.Fatal(e)
	}
	if w := api("GET", "/api/v1/holds?state=all&limit=1&cursor="+url.QueryEscape(a.Next), nil, ""); w.Code != 401 {
		t.Fatal("revoked administrator reused cursor", w.Code)
	}
}

func TestHoldAdministrationInventoryAndRetainedRepositoryRecovery(t *testing.T) {
	s, _, token, _ := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "holds", "format": "oci"}, "hold-admin-repository"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	digest := lifecyclePublish(t, s, token, "holds", "held")
	path := "app/manifests/sha256:" + digest
	endpoint := "/api/v1/repositories/holds/artifacts/lifecycle"
	hold := map[string]any{"action": "hold", "path": path, "digest": digest, "expected_revision": 0, "reason": "Preserve owned review evidence"}
	if w := api("PUT", endpoint, hold, "hold-admin-place"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	page := api("GET", "/api/v1/holds?state=all&limit=1", nil, "")
	if page.Code != 200 {
		t.Fatal("administrator cannot discover existing hold", page.Code, page.Body.String())
	}
	var value struct {
		Items []struct {
			Path   string
			Status string
		}
		Next string
	}
	if json.Unmarshal(page.Body.Bytes(), &value) != nil || len(value.Items) != 1 || value.Items[0].Path != path || value.Items[0].Status != "active" {
		t.Fatal("incorrect hold inventory", page.Body.String())
	}
	history := "/api/v1/repositories/holds/artifacts/lifecycle/history?path=" + url.QueryEscape(path) + "&limit=1"
	if w := api("GET", history, nil, ""); w.Code != 200 {
		t.Fatal("existing immutable hold history unavailable", w.Code, w.Body.String())
	}
	state := map[string]any{"action": "remove", "expected_revision": 0, "reason": "Retain repository during owned review"}
	if w := api("PUT", "/api/v1/repositories/holds/state", state, "hold-admin-remove-repository"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	release := map[string]any{"action": "release_hold", "path": path, "digest": digest, "expected_revision": 1, "reason": "Administrator releases review after retained repository inspection"}
	if w := api("PUT", endpoint, release, "hold-admin-release-retained"); w.Code != 200 {
		t.Fatal("administrator cannot release hold in retained repository", w.Code, w.Body.String())
	}
	if w := api("GET", "/api/v1/holds?state=released", nil, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", "/v2/holds/"+path, nil, ""); w.Code != 404 {
		t.Fatal("hold administration bypassed removed repository serving fence", w.Code)
	}
}
