//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func lifecycleHTTP(t *testing.T, s *Server, token string) func(string, string, any, string) *httptest.ResponseRecorder {
	t.Helper()
	return func(method, path string, value any, key string) *httptest.ResponseRecorder {
		t.Helper()
		body := ""
		if value != nil {
			raw, e := json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			body = string(raw)
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
}
func lifecyclePublish(t *testing.T, s *Server, token, repo, label string) string {
	t.Helper()
	data := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"label":"` + label + `"}}`
	r := httptest.NewRequest("PUT", "/v2/"+repo+"/app/manifests/latest", strings.NewReader(data))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", testOCIIndex)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	return crypt.Digest([]byte(data))
}

func TestLifecycleHTTPRestoreVerifiesBytesAndPreservesRetargets(t *testing.T) {
	s, _, token, i := schemaServer(t)
	request := lifecycleHTTP(t, s, token)
	if w := request("POST", "/api/v1/repositories", map[string]string{"name": "lifecycle", "format": "oci"}, "create-lifecycle"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	digest := lifecyclePublish(t, s, token, "lifecycle", "original")
	path := "app/manifests/sha256:" + digest
	api := "/api/v1/repositories/lifecycle/artifacts/lifecycle"
	if w := request("DELETE", "/v2/lifecycle/"+path, nil, ""); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/v2/lifecycle/app/manifests/latest", nil, ""); w.Code != 404 || !strings.Contains(w.Body.String(), "artifact_deleted") {
		t.Fatal(w.Code, w.Body.String())
	}
	input := map[string]any{"path": path, "digest": digest, "action": "restore", "expected_revision": 1, "reason": "verified recovery"}
	f, e := s.Blobs.Open(i.Tenant, digest)
	if e != nil {
		t.Fatal(e)
	}
	name := f.Name()
	_ = f.Close()
	if e = os.Rename(name, name+".owned-missing"); e != nil {
		t.Fatal(e)
	}
	w := request("PUT", api, input, "restore-object")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "integrity_failure") {
		t.Fatal("missing bytes restored", w.Code, w.Body.String())
	}
	if state, e := s.DB.ArtifactState(context.Background(), i, "lifecycle", path); e != nil || !state.Deleted || state.Revision != 1 {
		t.Fatal(state, e)
	}
	if e = os.Rename(name+".owned-missing", name); e != nil {
		t.Fatal(e)
	}
	newDigest := lifecyclePublish(t, s, token, "lifecycle", "new-target")
	w = request("PUT", api, input, "restore-object")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if e = os.Rename(name, name+".owned-missing"); e != nil {
		t.Fatal(e)
	}
	replay := request("PUT", api, input, "restore-object")
	if replay.Code != 200 || replay.Header().Get("Idempotent-Replayed") != "true" || replay.Body.String() != w.Body.String() {
		t.Fatal("restore replay", replay.Code, replay.Body.String())
	}
	if e = os.Rename(name+".owned-missing", name); e != nil {
		t.Fatal(e)
	}
	if w = request("GET", "/v2/lifecycle/app/manifests/latest", nil, ""); w.Code != 200 || w.Header().Get("Docker-Content-Digest") != "sha256:"+newDigest {
		t.Fatal("restore overwrote newer tag", w.Code, w.Body.String())
	}
	if w = request("GET", "/v2/lifecycle/"+path, nil, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	delete(input, "expected_revision")
	if w = request("PUT", api, input, "missing-revision"); w.Code != 400 {
		t.Fatal("missing revision", w.Code, w.Body.String())
	}
}

func TestLifecycleHTTPDeletedGroupCollisionNeverFallsThrough(t *testing.T) {
	s, _, token, _ := schemaServer(t)
	request := lifecycleHTTP(t, s, token)
	for _, repo := range []string{"first", "second"} {
		if w := request("POST", "/api/v1/repositories", map[string]string{"name": repo, "format": "oci"}, "create-"+repo); w.Code != 201 {
			t.Fatal(w.Body.String())
		}
	}
	digest := lifecyclePublish(t, s, token, "first", "same-bytes")
	lifecyclePublish(t, s, token, "second", "same-bytes")
	if w := request("POST", "/api/v1/repositories", store.Repository{Name: "group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}}, "create-group"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("DELETE", "/v2/first/app/manifests/sha256:"+digest, nil, ""); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, ref := range []string{"latest", "sha256:" + digest} {
		if w := request("GET", "/v2/group/app/manifests/"+ref, nil, ""); w.Code != 404 || !strings.Contains(w.Body.String(), "artifact_deleted") {
			t.Fatal("group resurrected deleted reference", ref, w.Code, w.Body.String())
		}
	}
	if w := request("GET", "/v2/group/app/tags/list", nil, ""); w.Code != 200 || strings.Contains(w.Body.String(), `"latest"`) {
		t.Fatal("discovery exposed lower collision", w.Code, w.Body.String())
	}
	if w := request("GET", "/v2/second/app/manifests/latest", nil, ""); w.Code != 200 {
		t.Fatal("deletion became global digest denial", w.Code, w.Body.String())
	}
	if w := request("PUT", "/api/v1/repositories/first/state", store.RepositoryStateRequest{Action: "suspend", ExpectedRevision: 0, Reason: "maintenance"}, "suspend-first"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/v2/group/app/manifests/latest", nil, ""); w.Code != 503 || !strings.Contains(w.Body.String(), "repository_suspended") {
		t.Fatal("suspended source fell through", w.Code, w.Body.String())
	}
}

func TestLifecycleHTTPProxyRefreshCannotRestoreLocalTombstone(t *testing.T) {
	s, _, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	request := lifecycleHTTP(t, s, token)
	raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	digest := crypt.Digest(raw)
	var hits atomic.Int32
	var missing atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if missing.Load() {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", testOCIIndex)
		w.Header().Set("Docker-Content-Digest", "sha256:"+digest)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(raw)
	}))
	defer origin.Close()
	repo := store.Repository{Name: "proxy", Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60, NegativeSeconds: 60}}}
	if w := request("POST", "/api/v1/repositories", repo, "create-proxy"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "app/manifests/sha256:" + digest
	if w := request("GET", "/v2/proxy/app/manifests/latest", nil, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("POST", "/api/v1/repositories", map[string]string{"name": "fallback", "format": "oci"}, "create-fallback"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	fallback := lifecyclePublish(t, s, token, "fallback", "lower-source")
	if w := request("POST", "/api/v1/repositories", store.Repository{Name: "proxy-group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{"proxy", "fallback"}}}, "create-proxy-group"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	input := store.ArtifactStateRequest{Path: path, Digest: digest, Action: "delete", ExpectedRevision: 0, Reason: "local removal"}
	if w := request("PUT", "/api/v1/repositories/proxy/artifacts/lifecycle", input, "delete-cached"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	before := hits.Load()
	r := httptest.NewRequest("GET", "/v2/proxy/"+path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cache-Control", "no-cache")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 404 || hits.Load() != before {
		t.Fatal("forced refresh fetched deleted path", w.Code, hits.Load(), before, w.Body.String())
	}
	missing.Store(true)
	r = httptest.NewRequest("GET", "/v2/proxy-group/app/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cache-Control", "no-cache")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "artifact_deleted") || hits.Load() != before {
		t.Fatal("known tombstone became upstream miss/group fallback", w.Code, hits.Load(), before, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/v2/proxy/app/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cache-Control", "no-cache")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 404 || hits.Load() != before {
		t.Fatal("forced tag refresh bypassed known tombstone", w.Code, hits.Load(), before)
	}
	if e := s.DB.Tx(context.Background(), i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(context.Background(), `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository='proxy'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.DB.OCISelection(context.Background(), i, "proxy", "app", "manifests", "latest"); !errors.Is(e, store.ErrDeleted) {
		t.Fatal("expired selection lost authoritative tombstone", e)
	}
	if _, e := s.DB.Artifact(context.Background(), i, "proxy", path); !errors.Is(e, store.ErrDeleted) {
		t.Fatal(e)
	}
	input.Action = "restore"
	input.ExpectedRevision = 1
	if w := request("PUT", "/api/v1/repositories/proxy/artifacts/lifecycle", input, "restore-cached"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/v2/proxy-group/app/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cache-Control", "no-cache")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Docker-Content-Digest") != "sha256:"+fallback {
		t.Fatal("ordinary source absence lost its existing group fallback", w.Code, w.Body.String())
	}
}

func TestLifecycleHTTPSuspendResumeFencesBlockedUpstream(t *testing.T) {
	s, _, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	request := lifecycleHTTP(t, s, token)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.Header().Set("Content-Type", testOCIIndex)
		w.Header().Set("Docker-Content-Digest", "sha256:"+crypt.Digest(raw))
		_, _ = w.Write(raw)
	}))
	defer origin.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	repo := store.Repository{Name: "blocked-source", Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}}}
	if w := request("POST", "/api/v1/repositories", repo, "create-blocked"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
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
	done := make(chan string, 1)
	go func() {
		r, _ := http.NewRequest("GET", endpoint.URL+"/v2/blocked-source/app/manifests/latest", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			done <- e.Error()
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		done <- fmt.Sprintf("%d %s", response.StatusCode, body)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never entered")
	}
	for n, action := range []string{"suspend", "resume"} {
		if w := request("PUT", "/api/v1/repositories/blocked-source/state", store.RepositoryStateRequest{Action: action, ExpectedRevision: int64(n), Reason: "fence in-flight source"}, "state-"+action); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	close(release)
	select {
	case response := <-done:
		if strings.HasPrefix(response, "200") {
			t.Fatal("old fetch published after resume", response)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not finish")
	}
	if _, e := s.DB.Artifact(context.Background(), i, "blocked-source", "app/manifests/sha256:"+crypt.Digest(raw)); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("superseded graph committed", e)
	}
}
