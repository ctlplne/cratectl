//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestConfigurationHTTPCredentialAuthorityRolesAndReplay(t *testing.T) {
	s, d, token, identity := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	ctx := context.Background()
	settings := store.RepositorySettings{Upstream: &upstream.Config{URL: "https://first.example/approved/", Networks: []string{"0.0.0.0/0"}, CredentialRef: "first", Authentication: "bearer"}}
	s.UpstreamCredentials[identity.Tenant+"/first"] = UpstreamCredential{Value: "owned-first-fixture", AllowedURL: settings.Upstream.URL}
	s.UpstreamCredentials[identity.Tenant+"/second"] = UpstreamCredential{Value: "owned-second-fixture", AllowedURL: "https://second.example/approved/"}
	if w := api("POST", "/api/v1/repositories", store.Repository{Name: "credential-source", Format: "generic", Mode: "proxy", Settings: settings}, "create-credential-source"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	endpoint := "/api/v1/repositories/credential-source/configuration"
	next := settings
	copy := *settings.Upstream
	next.Upstream = &copy
	next.Upstream.URL = "https://second.example/approved/"
	input := store.ConfigurationRequest{Settings: &next, Reason: "rotate approved source"}
	for _, dry := range []bool{true, false} {
		input.DryRun = dry
		if w := api("PUT", endpoint, input, "wrong-authority"); w.Code != 400 || !strings.Contains(w.Body.String(), "upstream_credential_authority") {
			t.Fatal("credential crossed authority", w.Code, w.Body.String())
		}
	}
	next.Upstream.CredentialRef = "second"
	input.DryRun = false
	first := api("PUT", endpoint, input, "credential-source-change")
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	delete(s.UpstreamCredentials, identity.Tenant+"/second")
	if w := api("PUT", endpoint, input, "credential-source-change"); w.Code != 200 || w.Header().Get("Idempotent-Replayed") != "true" || w.Body.String() != first.Body.String() {
		t.Fatal("committed replay depended on removed credential", w.Code, w.Body.String())
	}
	if w := api("PUT", endpoint, input, "different-source-change"); w.Code != 400 {
		t.Fatal("new operation accepted missing credential", w.Code, w.Body.String())
	}
	s.UpstreamCredentials[identity.Tenant+"/second"] = UpstreamCredential{Value: "owned-second-fixture", AllowedURL: next.Upstream.URL}
	if w := api("PUT", endpoint, input, "stale-source-change"); w.Code != 409 || !strings.Contains(w.Body.String(), "configuration_changed") {
		t.Fatal("stale configuration accepted", w.Code, w.Body.String())
	}
	for _, role := range []string{"reader", "writer"} {
		credential, e := crypt.Token()
		if e != nil {
			t.Fatal(e)
		}
		if e = store.Provision(ctx, d.OwnerDSN, identity.Tenant, role, role, credential, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		limited := lifecycleHTTP(t, s, credential)
		for _, path := range []string{endpoint, endpoint + "/history"} {
			if w := limited("GET", path, nil, ""); w.Code != 403 {
				t.Fatal("configuration exposed to nonadmin", role, w.Code)
			}
		}
		if w := limited("PUT", endpoint, input, "credential-source-change"); w.Code != 403 {
			t.Fatal("nonadmin replay admitted", role, w.Code)
		}
	}
	other, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, d.OwnerDSN, "configuration-other", "operator", "admin", other, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if w := lifecycleHTTP(t, s, other)("GET", endpoint+"/history", nil, ""); w.Code != 404 {
		t.Fatal("configuration crossed tenant", w.Code, w.Body.String())
	}
	for _, body := range []map[string]any{
		{"settings": next, "reason": "missing revision"},
		{"expected_revision": nil, "settings": next, "reason": "null revision"},
		{"expected_revision": 1, "settings": next, "reason": "unknown field", "credential_value": "owned-invalid-fixture"},
	} {
		if w := api("PUT", endpoint, body, "malformed-source-change"); w.Code != 400 {
			t.Fatal("malformed configuration accepted", w.Code, w.Body.String())
		}
	}
	if current, e := s.DB.Configuration(ctx, identity, "credential-source"); e != nil || current.SourceRevision != 1 {
		t.Fatal("rejections changed configuration", current, e)
	}
}

func TestConfigurationHTTPRevalidatesSourceAndNeverBorrowsValidatorsOr304Body(t *testing.T) {
	s, _, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	api := lifecycleHTTP(t, s, token)
	var aHits, bHits atomic.Int32
	var bad304 atomic.Bool
	var seenMu sync.Mutex
	seenValidators := []string{}
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aHits.Add(1)
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("ETag", `"same"`)
		_, _ = io.WriteString(w, "source A")
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits.Add(1)
		seenMu.Lock()
		seenValidators = append(seenValidators, r.Header.Get("If-None-Match"))
		seenMu.Unlock()
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("ETag", `"same"`)
		if bad304.Load() || r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(304)
			return
		}
		_, _ = io.WriteString(w, "source B")
	}))
	defer b.Close()
	settings := func(base string) store.RepositorySettings {
		return store.RepositorySettings{Upstream: &upstream.Config{URL: base + "/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 3600, StaleSeconds: 3600}}
	}
	first, next := settings(a.URL), settings(b.URL)
	if w := api("POST", "/api/v1/repositories", store.Repository{Name: "source-config", Format: "generic", Mode: "proxy", Settings: first}, "create-source-config"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", "/r/source-config/file", nil, ""); w.Code != 200 || w.Body.String() != "source A" {
		t.Fatal(w.Code, w.Body.String())
	}
	old, e := s.DB.Repository(context.Background(), i, "source-config")
	if e != nil {
		t.Fatal(e)
	}
	resolved, e := s.resolveProxy(context.Background(), i, old, "file", false)
	if e != nil {
		t.Fatal(e)
	}
	endpoint := "/api/v1/repositories/source-config/configuration"
	input := store.ConfigurationRequest{ExpectedRevision: 0, Settings: &next, Reason: "change approved upstream", DryRun: true}
	if w := api("PUT", endpoint, input, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", "/r/source-config/file", nil, ""); w.Code != 200 || w.Body.String() != "source A" || bHits.Load() != 0 {
		t.Fatal("preview performed effects", w.Code, w.Body.String())
	}
	input.DryRun = false
	firstResponse := api("PUT", endpoint, input, "change-source")
	if firstResponse.Code != 200 {
		t.Fatal(firstResponse.Code, firstResponse.Body.String())
	}
	if _, e = s.guardResolved(context.Background(), i, resolved); !errors.Is(e, store.ErrSourceChanged) {
		t.Fatal("old selected bytes survived source change", e)
	}
	if w := api("GET", "/r/source-config/file", nil, ""); w.Code != 200 || w.Body.String() != "source B" {
		t.Fatal("fresh cache reused old authority", w.Code, w.Body.String())
	}
	seenMu.Lock()
	for _, header := range seenValidators {
		if header != "" {
			t.Error("forwarded old source validator")
		}
	}
	seenMu.Unlock()
	input.ExpectedRevision = 1
	input.Reason = "refresh credential binding"
	bad304.Store(true)
	if w := api("PUT", endpoint, input, "credential-epoch"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := api("GET", "/r/source-config/file", nil, "")
	if w.Code == 200 || w.Code == 304 {
		t.Fatal("304 borrowed prior source body", w.Code, w.Body.String())
	}
	bad304.Store(false)
	r := httptest.NewRequest("GET", "/r/source-config/file", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cache-Control", "no-cache")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "source B" {
		t.Fatal("invalid 304 left a live retrieval stuck", w.Code, w.Body.String())
	}
	rollback := store.ConfigurationRequest{ExpectedRevision: 2, Settings: &first, Reason: "rollback keeps a new revision"}
	if w := api("PUT", endpoint, rollback, "rollback-source"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	replay := api("PUT", endpoint, store.ConfigurationRequest{ExpectedRevision: 0, Settings: &next, Reason: "change approved upstream"}, "change-source")
	if replay.Code != 200 || replay.Header().Get("Idempotent-Replayed") != "true" || replay.Body.String() != firstResponse.Body.String() {
		t.Fatal("replay lost original response", replay.Code, replay.Body.String())
	}
	if current, e := s.DB.Configuration(context.Background(), i, "source-config"); e != nil || current.SourceRevision != 3 || current.Settings.Upstream.URL != first.Upstream.URL {
		t.Fatal("replay performed old transition", current, e)
	}
	if w := api("GET", "/r/source-config/file", nil, ""); w.Code != 200 || w.Body.String() != "source A" {
		t.Fatal("rollback reused B cache", w.Code, w.Body.String())
	}
	if aHits.Load() != 2 {
		t.Fatal("unexpected source A accesses", aHits.Load())
	}
	if w := api("GET", endpoint+"/history?limit=1", nil, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	} else {
		var out struct {
			Items []store.ConfigurationChange `json:"items"`
			After int64                       `json:"after"`
		}
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Items) != 1 || out.After != 1 {
			t.Fatal(w.Body.String())
		}
	}
}

func TestConfigurationHTTPFencesRunningFillAndGroupSelection(t *testing.T) {
	s, _, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	api := lifecycleHTTP(t, s, token)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "old source bytes")
	}))
	defer origin.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	settings := store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60}}
	if w := api("POST", "/api/v1/repositories", store.Repository{Name: "running-source", Format: "generic", Mode: "proxy", Settings: settings}, "create-running"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	endpoint := httptest.NewServer(s)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		endpoint.Close()
	}()
	done := make(chan int, 1)
	go func() {
		r, _ := http.NewRequest("GET", endpoint.URL+"/r/running-source/file", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			done <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		done <- response.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not enter")
	}
	if w := api("PUT", "/api/v1/repositories/running-source/configuration", store.ConfigurationRequest{ExpectedRevision: 0, Settings: &settings, Reason: "same settings still fence credentials"}, "fence-running"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	close(release)
	select {
	case status := <-done:
		if status == 200 {
			t.Fatal("old running fill served after configuration change")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old fill did not finish")
	}
	if _, e := s.DB.Artifact(context.Background(), i, "running-source", "file"); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("old fill reference committed", e)
	}
	for _, repo := range []string{"group-first", "group-second"} {
		if w := api("POST", "/api/v1/repositories", map[string]string{"name": repo, "format": "generic"}, "create-"+repo); w.Code != 201 {
			t.Fatal(w.Body.String())
		}
		if e := s.DB.Publish(context.Background(), i, repo, []store.Artifact{{Path: "file", Digest: strings.Repeat("a", 64), Size: 3, MediaType: "text/plain"}}); e != nil {
			t.Fatal(e)
		}
	}
	groupSettings := store.RepositorySettings{Members: []string{"group-first", "group-second"}}
	if w := api("POST", "/api/v1/repositories", store.Repository{Name: "versioned-group", Format: "generic", Mode: "group", Settings: groupSettings}, "create-versioned-group"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	group, e := s.DB.Repository(context.Background(), i, "versioned-group")
	if e != nil {
		t.Fatal(e)
	}
	selected, e := s.resolve(context.Background(), i, group, "file", false)
	if e != nil {
		t.Fatal(e)
	}
	groupSettings.Members = []string{"group-second"}
	if w := api("PUT", "/api/v1/repositories/versioned-group/configuration", store.ConfigurationRequest{ExpectedRevision: 0, Settings: &groupSettings, Reason: "remove prior group owner"}, "remove-group-member"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, e = s.guardResolved(context.Background(), i, selected); !errors.Is(e, store.ErrSourceChanged) {
		t.Fatal("removed group source served selected bytes", e)
	}
}
