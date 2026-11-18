// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"ctlplne.dev/cratectl/internal/configfile"
)

const ownedRepositoryManifest = `{"version":1,"tenant":"cratectl-manifest","name":"cratectl-packages","format":"npm","access":"restricted","require_review":true}`

func TestRepositoryManifestRequiresExactFields(t *testing.T) {
	for _, input := range []string{
		strings.Replace(ownedRepositoryManifest, "require_review", "Require_Review", 1),
		strings.Replace(ownedRepositoryManifest, `"require_review":true`, `"require_review":true,"require_review":false`, 1),
		strings.Replace(ownedRepositoryManifest, `,"require_review":true`, "", 1),
		strings.Replace(ownedRepositoryManifest, `"require_review":true`, `"require_review":null`, 1),
		strings.Replace(ownedRepositoryManifest, `"require_review":true`, `"require_review":"true"`, 1),
		ownedRepositoryManifest + `{}`,
		`null`,
	} {
		var manifest repositoryManifestDocument
		if decodeRepositoryManifest([]byte(input), &manifest) {
			t.Fatalf("accepted ambiguous manifest %s", input)
		}
	}
	var manifest repositoryManifestDocument
	if !decodeRepositoryManifest([]byte(ownedRepositoryManifest), &manifest) || !manifest.RequireReview || manifest.Access != "restricted" {
		t.Fatal("exact manifest was refused")
	}
	plan := planRepository("https://example.test:38443", manifest, nil)
	otherAuthority := planRepository("https://other.test:38443", manifest, nil)
	manifest.Tenant = "cratectl-other"
	otherTenant := planRepository(plan.Authority, manifest, nil)
	if !repositoryPlanDigest.MatchString(plan.ApprovalSHA256) ||
		plan.ApprovalSHA256 == otherTenant.ApprovalSHA256 || plan.ApprovalSHA256 == otherAuthority.ApprovalSHA256 {
		t.Fatal("approval failed to bind the tenant and authority")
	}
}

func TestRepositoryManifestPlanApplyImportAndDrift(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, content []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := configfile.WriteNewPrivate(path, content); err != nil {
			t.Fatal(err)
		}
		return path
	}
	manifest := write("manifest.json", []byte(ownedRepositoryManifest))
	tokenFile := write("token", []byte("owned-test-token\n"))
	var mu sync.Mutex
	role, state, configuredTenant := "admin", "active", "cratectl-manifest"
	created, ambiguousCreate, brokenRead := false, true, false
	var writes, repositoryReads int
	var createdKey string
	jsonBody := func(w http.ResponseWriter, status int, raw string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, raw)
	}
	const configurationPath = repositoriesAPI + "/cratectl-packages/configuration"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer owned-test-token" {
			t.Error("missing configured private authentication")
			w.WriteHeader(401)
			return
		}
		switch [2]string{r.Method, r.URL.Path} {
		case [2]string{"GET", "/api/v1/session"}:
			jsonBody(w, 200, `{"tenant":"`+configuredTenant+`","role":"`+role+`","formats":["npm"]}`)
		case [2]string{"GET", configurationPath}:
			repositoryReads++
			if brokenRead {
				jsonBody(w, 404, `{"error":{"code":"unknown_route"}}`)
			} else if !created {
				jsonBody(w, 404, `{"error":{"code":"not_found"}}`)
			} else {
				jsonBody(w, 200, `{"name":"cratectl-packages","format":"npm","mode":"hosted","access":"restricted","require_review":true,"settings":{}}`)
			}
		case [2]string{"GET", repositoriesAPI + "/cratectl-packages/state"}:
			jsonBody(w, 200, `{"repository":"cratectl-packages","state":"`+state+`","revision":1}`)
		case [2]string{"POST", repositoriesAPI}:
			var request map[string]any
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil || !reflect.DeepEqual(request, map[string]any{
				"name": "cratectl-packages", "format": "npm", "mode": "hosted",
				"access": "restricted", "require_review": true,
			}) {
				t.Errorf("unexpected creation request %v, %v", request, err)
			}
			writes++
			createdKey = r.Header.Get("Idempotency-Key")
			created = true
			if ambiguousCreate {
				jsonBody(w, 503, `{"error":{"code":"simulated_response_loss"}}`)
			} else {
				jsonBody(w, 201, `{}`)
			}
		default:
			t.Errorf("unexpected management request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	config, err := json.Marshal(configfile.Client{Version: 1, URL: server.URL, TokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	configPath := write("client.json", config)
	call := func(command string, args ...string) ([]byte, error) {
		t.Helper()
		var output bytes.Buffer
		err := runRepositoryManifest(append([]string{"--config", configPath}, args...), command, &output)
		return output.Bytes(), err
	}
	planCall := func() (repositoryPlan, error) {
		t.Helper()
		raw, err := call("repository-plan", "--manifest", manifest)
		var plan repositoryPlan
		if err == nil {
			err = json.Unmarshal(raw, &plan)
		}
		return plan, err
	}
	plan, err := planCall()
	if err != nil || plan.Action != "create" || plan.Current != nil || !repositoryPlanDigest.MatchString(plan.ApprovalSHA256) {
		t.Fatalf("creation plan %+v, %v", plan, err)
	}
	apply := func(approval string) (repositoryPlan, error) {
		t.Helper()
		raw, err := call("repository-apply", "--manifest", manifest, "--approve", approval)
		var result repositoryPlan
		if len(raw) > 0 {
			if decodeErr := json.Unmarshal(raw, &result); decodeErr != nil {
				t.Fatal(decodeErr)
			}
		}
		return result, err
	}
	if _, err = apply(strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "repository_plan_changed") {
		t.Fatalf("wrong approval was accepted: %v", err)
	}
	if _, err = apply(plan.ApprovalSHA256); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("ambiguous create returned success: %v", err)
	}
	retry, err := apply(plan.ApprovalSHA256)
	if err != nil || retry.Action != "unchanged" || retry.Current == nil || !retry.Current.RequireReview {
		t.Fatalf("response loss recovery %+v, %v", retry, err)
	}
	mu.Lock()
	writesAfterRetry, key := writes, createdKey
	mu.Unlock()
	if writesAfterRetry != 1 || key != "repository-create-"+plan.ApprovalSHA256 {
		t.Fatal("creation or retry used an unexpected write or idempotency key")
	}
	raw, err := call("repository-import", "--tenant", "cratectl-manifest", "--name", "cratectl-packages")
	if err != nil {
		t.Fatal(err)
	}
	var exported repositoryManifestDocument
	if !decodeRepositoryManifest(raw, &exported) || exported != plan.Desired {
		t.Fatalf("unexpected imported manifest %s", raw)
	}
	mu.Lock()
	state = "suspended"
	mu.Unlock()
	drift, err := planCall()
	if err != nil || drift.Action != "drift" || !reflect.DeepEqual(drift.Drift, []string{"state"}) {
		t.Fatalf("lifecycle drift %+v, %v", drift, err)
	}
	if replay, err := apply(plan.ApprovalSHA256); err == nil || replay.Action != "drift" {
		t.Fatalf("stale approval did not surface drift %+v, %v", replay, err)
	}
	if _, err = call("repository-import", "--tenant", "cratectl-manifest", "--name", "cratectl-packages"); err == nil {
		t.Fatal("suspended repository was imported as active")
	}
	mu.Lock()
	role = "reader"
	priorReads := repositoryReads
	mu.Unlock()
	if _, err = planCall(); err == nil || !strings.Contains(err.Error(), "repository_manifest_tenant_access") {
		t.Fatalf("reader inspected administrator projection: %v", err)
	}
	mu.Lock()
	role = "admin"
	configuredTenant = "cratectl-other"
	mu.Unlock()
	if _, err = apply(plan.ApprovalSHA256); err == nil || !strings.Contains(err.Error(), "repository_manifest_tenant_access") {
		t.Fatalf("another tenant passed the apply guard: %v", err)
	}
	mu.Lock()
	actualReads, actualWrites := repositoryReads, writes
	configuredTenant = "cratectl-manifest"
	brokenRead = true
	mu.Unlock()
	if actualReads != priorReads || actualWrites != writesAfterRetry {
		t.Fatal("permission or drift failures reached protected writes or cross-tenant reads")
	}
	if _, err = planCall(); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("an unknown route was treated as an absent repository: %v", err)
	}
}
