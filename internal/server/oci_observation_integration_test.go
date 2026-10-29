//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestOCIProxyReferrersRetainRetiredObservationsAndApplySubjectPolicy(t *testing.T) {
	s, d, token, identity := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	admin := lifecycleHTTP(t, s, token)
	readerToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(context.Background(), d.OwnerDSN, identity.Tenant, "reader", "reader", readerToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	reader := lifecycleHTTP(t, s, readerToken)
	root := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	rootDigest := "sha256:" + crypt.Digest(root)
	objects := map[string][]byte{rootDigest: root}
	descriptors := []store.OCIReferrer{}
	digests := map[string]string{}
	for _, label := range []string{"retired", "denied", "visible"} {
		body, e := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": testOCIIndex, "manifests": []any{}, "artifactType": "application/vnd.cratectl.proof", "subject": store.OCIDescriptor{MediaType: testOCIIndex, Digest: rootDigest, Size: int64(len(root))}, "annotations": map[string]string{"label": label}})
		if e != nil {
			t.Fatal(e)
		}
		digest := "sha256:" + crypt.Digest(body)
		digests[label] = digest
		objects[digest] = body
		descriptors = append(descriptors, store.OCIReferrer{OCIDescriptor: store.OCIDescriptor{MediaType: testOCIIndex, Digest: digest, Size: int64(len(body))}, ArtifactType: "application/vnd.cratectl.proof"})
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		if r.URL.Path == "/v2/app/referrers/"+rootDigest {
			w.Header().Set("Content-Type", testOCIIndex)
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2, "mediaType": testOCIIndex, "manifests": descriptors})
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v2/app/manifests/")
		if body, ok := objects[ref]; ok {
			w.Header().Set("Content-Type", testOCIIndex)
			w.Header().Set("Docker-Content-Digest", ref)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(404)
	}))
	defer origin.Close()
	repository := store.Repository{Name: "referrer-observations", Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60}}}
	if w := admin("POST", "/api/v1/repositories", repository, "create-referrer-observations"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "/v2/referrer-observations/app/referrers/" + rootDigest
	discover := func(expected ...string) {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+readerToken)
		r.Header.Set("Cache-Control", "no-cache")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("referrer refresh lost visible peers", w.Code, w.Body.String())
		}
		var document struct {
			Manifests []store.OCIReferrer `json:"manifests"`
		}
		if json.Unmarshal(w.Body.Bytes(), &document) != nil || len(document.Manifests) != len(expected) {
			t.Fatal("referrers", w.Body.String(), expected)
		}
		seen := map[string]bool{}
		for _, descriptor := range document.Manifests {
			seen[descriptor.Digest] = true
		}
		for _, label := range expected {
			if !seen[digests[label]] {
				t.Fatal("referrer missing", label, w.Body.String())
			}
		}
	}
	discover("retired", "denied", "visible")
	input := store.ArtifactStateRequest{Path: "app/manifests/" + digests["retired"], Digest: strings.TrimPrefix(digests["retired"], "sha256:"), Action: "delete", Reason: "retire observed attachment"}
	if w := admin("PUT", "/api/v1/repositories/referrer-observations/artifacts/lifecycle", input, "delete-referrer-observation"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover("denied", "visible")
	deny := func(digest, key string) {
		t.Helper()
		if w := admin("PUT", "/api/v1/repositories/referrer-observations/decisions", map[string]string{"path": "app/manifests/" + digest, "digest": strings.TrimPrefix(digest, "sha256:"), "decision": "denied"}, key); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	deny(digests["denied"], "deny-referrer-observation")
	discover("visible")
	if w := reader("GET", "/v2/referrer-observations/"+input.Path, nil, ""); w.Code != 404 {
		t.Fatal("discovery revived retired attachment", w.Code)
	}
	input.Action = "restore"
	input.ExpectedRevision = 1
	if w := admin("PUT", "/api/v1/repositories/referrer-observations/artifacts/lifecycle", input, "restore-referrer-observation"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover("retired", "visible")
	deny(rootDigest, "deny-referrer-subject")
	if w := reader("GET", path, nil, ""); w.Code != 403 {
		t.Fatal("referrer discovery ignored current subject denial", w.Code, w.Body.String())
	}
}

func TestOCIProxyDiscoveryObservesRetiredAndDeniedPeersWithoutRevivingThem(t *testing.T) {
	s, d, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	admin := lifecycleHTTP(t, s, token)
	readerToken, _ := crypt.Token()
	if e := store.Provision(context.Background(), d.OwnerDSN, i.Tenant, "reader", "reader", readerToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	reader := lifecycleHTTP(t, s, readerToken)
	index := func(label string) []byte {
		return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"label":"` + label + `"}}`)
	}
	old, live, safe := index("old"), index("live"), index("safe")
	objects := map[string][]byte{}
	tags := map[string]string{}
	for name, data := range map[string][]byte{"old": old, "live": live, "safe": safe} {
		digest := "sha256:" + crypt.Digest(data)
		tags[name] = digest
		objects[digest] = data
	}
	child := []byte("retained child bytes")
	childDigest := "sha256:" + crypt.Digest(child)
	var mu sync.RWMutex
	blobRequests := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Cache-Control", "max-age=60")
		if r.URL.Path == "/v2/app/tags/list" {
			names := []string{}
			for name := range tags {
				names = append(names, name)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "app", "tags": names})
			return
		}
		if r.URL.Path == "/v2/app/blobs/"+childDigest {
			blobRequests++
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Docker-Content-Digest", childDigest)
			_, _ = w.Write(child)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v2/app/manifests/")
		if digest, ok := tags[ref]; ok {
			ref = digest
		}
		data, ok := objects[ref]
		if !ok {
			w.WriteHeader(404)
			return
		}
		media := testOCIIndex
		var m struct {
			Media string `json:"mediaType"`
		}
		_ = json.Unmarshal(data, &m)
		if m.Media != "" {
			media = m.Media
		}
		w.Header().Set("Content-Type", media)
		w.Header().Set("Docker-Content-Digest", ref)
		_, _ = w.Write(data)
	}))
	defer origin.Close()
	repo := store.Repository{Name: "observations", Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60}}}
	if w := admin("POST", "/api/v1/repositories", repo, "create-observations"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover := func(endpoint string, expected ...string) {
		t.Helper()
		r := httptest.NewRequest("GET", "/v2/"+endpoint+"/app/tags/list", nil)
		r.Header.Set("Authorization", "Bearer "+readerToken)
		r.Header.Set("Cache-Control", "no-cache")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("catalog refresh lost visible peers", w.Code, w.Body.String())
		}
		var v struct {
			Tags []string `json:"tags"`
		}
		if json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal(w.Body.String())
		}
		actual := map[string]bool{}
		for _, tag := range v.Tags {
			actual[tag] = true
		}
		if len(actual) != len(expected) {
			t.Fatal("visible tags", v.Tags, "want", expected)
		}
		for _, tag := range expected {
			if !actual[tag] {
				t.Fatal("missing tag", tag, v.Tags)
			}
		}
	}
	discover("observations", "old", "live", "safe")
	oldPath := "app/manifests/sha256:" + crypt.Digest(old)
	input := store.ArtifactStateRequest{Path: oldPath, Digest: crypt.Digest(old), Action: "delete", ExpectedRevision: 0, Reason: "retire source observation"}
	if w := admin("PUT", "/api/v1/repositories/observations/artifacts/lifecycle", input, "delete-observed"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover("observations", "live", "safe")
	if w := reader("GET", "/v2/observations/"+oldPath, nil, ""); w.Code != 404 {
		t.Fatal("catalog revived tombstone", w.Code, w.Body.String())
	}
	if w := admin("PUT", "/api/v1/repositories/observations/decisions", map[string]string{"path": "app/manifests/sha256:" + crypt.Digest(live), "digest": crypt.Digest(live), "decision": "denied"}, "deny-observed"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover("observations", "safe")
	if w := reader("GET", "/v2/observations/app/manifests/live", nil, ""); w.Code != 403 {
		t.Fatal("catalog reset denial", w.Code, w.Body.String())
	}
	if w := admin("POST", "/api/v1/repositories", map[string]string{"name": "observation-lower", "format": "oci"}, "create-lower"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	r := httptest.NewRequest("PUT", "/v2/observation-lower/app/manifests/old", strings.NewReader(string(old)))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", testOCIIndex)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if w := admin("POST", "/api/v1/repositories", store.Repository{Name: "observation-group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{"observations", "observation-lower"}}}, "create-group"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover("observation-group", "safe")
	if w := reader("GET", "/v2/observations/app/blobs/"+childDigest, nil, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	childPath := "app/blobs/" + childDigest
	input = store.ArtifactStateRequest{Path: childPath, Digest: crypt.Digest(child), Action: "delete", ExpectedRevision: 0, Reason: "retire before new parent"}
	if w := admin("PUT", "/api/v1/repositories/observations/artifacts/lifecycle", input, "delete-child"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	parent, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": testOCIImage, "config": map[string]any{"mediaType": "text/plain", "digest": childDigest, "size": len(child)}, "layers": []any{}})
	mu.Lock()
	parentDigest := "sha256:" + crypt.Digest(parent)
	objects[parentDigest] = parent
	tags["blocked-child"] = parentDigest
	before := blobRequests
	mu.Unlock()
	discover("observations", "safe")
	mu.RLock()
	after := blobRequests
	mu.RUnlock()
	if after != before {
		t.Fatal("discovery downloaded a known retired child", before, after)
	}
	if w := reader("GET", "/v2/observations/app/manifests/blocked-child", nil, ""); w.Code != 404 {
		t.Fatal("new parent bypassed child tombstone", w.Code, w.Body.String())
	}
	input.Action = "restore"
	input.ExpectedRevision = 1
	if w := admin("PUT", "/api/v1/repositories/observations/artifacts/lifecycle", input, "restore-child"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	discover("observations", "safe", "blocked-child")
	mu.Lock()
	replacement := index("new tag target")
	newDigest := "sha256:" + crypt.Digest(replacement)
	objects[newDigest] = replacement
	tags["old"] = newDigest
	mu.Unlock()
	discover("observations", "safe", "blocked-child", "old")
	state, e := s.DB.ArtifactState(context.Background(), i, "observations", oldPath)
	if e != nil || !state.Deleted || state.Revision != 1 {
		t.Fatal("tag retarget changed old canonical lifecycle", state, e)
	}
}
