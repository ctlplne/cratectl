//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestOCINativeProcessDescriptorURLsAndRetainedRefresh(t *testing.T) {
	if os.Getenv("CRATECTL_DSN") == "" || os.Getenv("CRATECTL_OWNER_DSN") == "" {
		t.Fatal("Real runtime/owner PostgreSQL configuration required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), "test-a", "oci-descriptors", "admin", token, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	identity, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	nonce, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	nonceAfter, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	var refQuery atomic.Value
	refQuery.Store("reference=" + nonce)
	config := []byte("{}")
	payload := bytes.Repeat([]byte("opaque descriptor payload\n"), 40)
	var corrupt atomic.Bool
	var deliveries, originManifests, refIndexRequests, legacyRequests atomic.Int32
	var legacyReferrers atomic.Bool
	var manifest, referrer []byte
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "alternate" || password != "owned-descriptor-password" || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" {
			t.Error("alternate source credential boundary changed")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60, stale-if-error=120")
		switch r.URL.Path {
		case "/objects/missing":
			w.WriteHeader(404)
		case "/objects/config":
			w.Write(config)
		case "/objects/referrer":
			if r.URL.RawQuery != refQuery.Load().(string) {
				t.Error("expired referent advertisement reused")
				w.WriteHeader(403)
				return
			}
			w.Header().Set("Content-Type", nativeOCIImage)
			w.Write(referrer)
		case "/objects/manifest":
			w.Header().Set("Content-Type", nativeOCIImage)
			w.Write(manifest)
		case "/objects/payload":
			if r.URL.RawQuery != "proof="+nonce+"&scope=owned%2Fblob&order=two&order=one" {
				t.Error("opaque descriptor URL query changed")
				w.WriteHeader(403)
				return
			}
			if corrupt.Load() {
				w.Write(bytes.Repeat([]byte("x"), len(payload)))
				return
			}
			w.Write(payload)
		default:
			w.WriteHeader(404)
		}
	}))
	defer cdn.Close()
	descriptor := func(data []byte, media string, urls []string) map[string]any {
		out := map[string]any{"mediaType": media, "digest": "sha256:" + crypt.Digest(data), "size": len(data)}
		if urls != nil {
			out["urls"] = urls
		}
		return out
	}
	layer := descriptor(payload, "application/octet-stream", []string{cdn.URL + "/objects/missing", cdn.URL + "/objects/payload?proof=" + nonce + "&scope=owned%2Fblob&order=two&order=one"})
	secondLayer := descriptor(payload, "application/octet-stream", []string{cdn.URL + "/objects/payload?proof=" + nonce + "&scope=owned%2Fblob&order=two&order=one"})
	layer["urls"] = []string{cdn.URL + "/objects/missing"}
	manifest, _ = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": nativeOCIImage, "config": descriptor(config, "application/vnd.example.config", []string{cdn.URL + "/objects/config"}), "layers": []any{layer, secondLayer}})
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{descriptor(manifest, nativeOCIImage, []string{cdn.URL + "/objects/manifest"})}})
	referrer, _ = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": nativeOCIImage, "artifactType": "application/vnd.example.proof", "subject": descriptor(index, "application/vnd.oci.image.index.v1+json", nil), "config": descriptor(config, "application/vnd.example.config", []string{cdn.URL + "/objects/config"}), "layers": []any{layer, secondLayer}})
	refIndex := func(include bool) []byte {
		entries := []any{}
		if include {
			entries = append(entries, descriptor(referrer, nativeOCIImage, []string{cdn.URL + "/objects/referrer?" + refQuery.Load().(string)}))
		}
		raw, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries})
		return raw
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-descriptor-origin" {
			t.Error("registry credential missing")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		if r.URL.Path == "/v2/app/referrers/sha256:"+crypt.Digest(index) {
			refIndexRequests.Add(1)
			if legacyReferrers.Load() {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			if r.URL.Query().Get("cursor") == "two" {
				w.Write(refIndex(true))
				return
			}
			w.Header().Set("Link", `<?cursor=two>; rel=next`)
			w.Write(refIndex(false))
			return
		}
		if r.URL.Path == "/v2/app/manifests/sha256-"+crypt.Digest(index) {
			legacyRequests.Add(1)
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Write(refIndex(true))
			return
		}

		if r.URL.Path == "/v2/app/manifests/latest" || r.URL.Path == "/v2/app/manifests/sha256:"+crypt.Digest(index) {
			originManifests.Add(1)
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Write(index)
			return
		}
		w.WriteHeader(404)
	}))
	defer origin.Close()
	private := retainedNativeDir(t)
	credentials := filepath.Join(private, "upstreams.json")
	raw, _ := json.Marshal(map[string]any{"test-a/origin": map[string]string{"value": "owned-descriptor-origin", "allowed_url": origin.URL + "/v2/"}, "test-a/alternate": map[string]string{"value": "alternate:owned-descriptor-password", "allowed_url": cdn.URL + "/objects/", "authentication": "basic"}})
	if e = os.WriteFile(credentials, raw, 0600); e != nil {
		t.Fatal(e)
	}
	binary, e := filepath.Abs("../../bin/cratectld")
	if e != nil {
		t.Fatal(e)
	}
	serverBytes, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal("Built native server required:", e)
	}
	t.Log("Native server SHA-256:", crypt.Digest(serverBytes))
	var process *exec.Cmd
	var log *os.File
	stop := func() {
		if process == nil {
			return
		}
		process.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			process.Process.Kill()
			<-done
		}
		process = nil
		log.Close()
	}
	defer stop()
	start := func() {
		t.Helper()
		log, e = os.OpenFile(filepath.Join(private, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		process = exec.CommandContext(ctx, binary, "serve", "--listen", "127.0.0.1:38443", "--public-url", "http://127.0.0.1:38443", "--dev-loopback-http", "--objects", filepath.Join(private, "objects"), "--upstream-credentials", credentials, "--allow-private-upstreams", "127.0.0.1/32")
		process.Env = append(nativeClientEnvironment(), "CRATECTL_DSN="+os.Getenv("CRATECTL_DSN"))
		process.Stdout = log
		process.Stderr = log
		if e = process.Start(); e != nil {
			t.Fatal(e)
		}
		client := &http.Client{Timeout: time.Second}
		for n := 0; n < 100; n++ {
			response, e := client.Get("http://127.0.0.1:38443/health/ready")
			if e == nil {
				response.Body.Close()
				if response.StatusCode == 200 {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("Owned native process readiness failed; retained private log")
	}
	repo := store.Repository{Name: fmt.Sprintf("oci-descriptor-%d", time.Now().UnixNano()), Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "origin"}, DownloadSources: []upstream.Config{{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "alternate", Authentication: "basic", AllowSignedQuery: true}}, Cache: store.CacheSettings{FreshSeconds: 60, StaleSeconds: 120}}}
	create := func(value store.Repository) {
		t.Helper()
		if _, e := db.Mutate(ctx, identity, "", "", "repository.created", func(tx pgx.Tx) (any, int, error) { return value, 201, store.CreateRepository(ctx, tx, identity, value) }); e != nil {
			t.Fatal(e)
		}
	}
	create(repo)
	group := store.Repository{Name: repo.Name + "-group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{repo.Name}}}
	create(group)
	start()
	oras, e := filepath.Abs("../../.cache/bin/oras")
	if e != nil {
		t.Fatal(e)
	}
	auth := filepath.Join(private, "registry.json")
	run := func(input string, wantFailure bool, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, oras, args...)
		cmd.Env = nativeClientEnvironment()
		cmd.Dir = private
		cmd.Stdin = strings.NewReader(input)
		out, e := cmd.CombinedOutput()
		retainNativeOutput(t, private, out)
		if wantFailure {
			if e == nil {
				t.Fatal("invalid native descriptor copy succeeded")
			}
			return
		}
		if e != nil {
			t.Fatalf("stock ORAS failed: %v %s", e, strings.ReplaceAll(strings.ReplaceAll(string(out), token, "[REDACTED]"), nonce, "[REDACTED]"))
		}
	}
	run(token+"\n", false, "login", "--plain-http", "--registry-config", auth, "--username", "token", "--password-stdin", "127.0.0.1:38443")
	os.Chmod(auth, 0600)
	copyImage := func(name, label string, wantFailure bool) {
		t.Helper()
		run("", wantFailure, "copy", "--from-plain-http", "--from-registry-config", auth, "--to-oci-layout", "127.0.0.1:38443/"+name+"/app:latest", filepath.Join(private, label)+":copy")
	}
	copyImage(repo.Name, "proxy", false)
	copyImage(group.Name, "group", false)
	for _, data := range [][]byte{index, manifest, config, payload} {
		actual, e := os.ReadFile(filepath.Join(private, "group", "blobs", "sha256", crypt.Digest(data)))
		if e != nil || !bytes.Equal(actual, data) {
			t.Fatal("native copied graph differs from exact descriptor bytes", e)
		}
	}
	t.Log("PASS: native server and stock ORAS proxy/group copy index, child manifest, config and signed alternate layer with isolated credentials")
	request := func(name, kind, digest string) (int, []byte) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:38443/v2/"+name+"/app/"+kind+"/sha256:"+digest, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Cache-Control", "no-cache")
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, data
	}
	before := originManifests.Load()
	stop()
	start()
	for _, entry := range []struct {
		kind string
		data []byte
	}{{"blobs", payload}, {"manifests", manifest}} {
		path := "app/" + entry.kind + "/sha256:" + crypt.Digest(entry.data)
		if _, e = db.Mutate(ctx, identity, "", "", "proxy.cache.invalidated", func(tx pgx.Tx) (any, int, error) {
			v, e := store.InvalidateRetrieval(ctx, tx, identity, repo.Name, path)
			return v, 200, e
		}); e != nil {
			t.Fatal(e)
		}
		if code, data := request(group.Name, entry.kind, crypt.Digest(entry.data)); code != 200 || !bytes.Equal(data, entry.data) {
			t.Fatalf("direct retained descriptor refresh failed after process restart: %d", code)
		}
	}
	if originManifests.Load() != before {
		t.Fatal("direct member refresh re-fetched a mutable/parent source manifest")
	}
	t.Log("PASS: real native process restart followed by invalidated direct layer/manifest pins recovers locators from verified retained parent bytes")
	if code, data := request(group.Name, "referrers", crypt.Digest(index)); code != 200 || !bytes.Contains(data, []byte(crypt.Digest(referrer))) {
		t.Fatal("source referrer descriptor URL did not publish a complete native catalog")
	}
	run("", false, "discover", "--plain-http", "--registry-config", auth, "--distribution-spec", "v1.1-referrers-api", "--depth", "1", "127.0.0.1:38443/"+group.Name+"/app@sha256:"+crypt.Digest(index))
	beforeRef := refIndexRequests.Load()
	refQuery.Store("reference=" + nonceAfter)
	stop()
	start()
	if code, data := request(group.Name, "manifests", crypt.Digest(referrer)); code != 200 || !bytes.Equal(data, referrer) {
		t.Fatalf("retained referrer locator rediscovery failed: %d", code)
	}
	if refIndexRequests.Load() != beforeRef+2 {
		t.Fatal("direct referent did not rewalk both current source catalog pages")
	}
	legacyReferrers.Store(true)
	if code, data := request(group.Name, "manifests", crypt.Digest(referrer)); code != 200 || !bytes.Equal(data, referrer) {
		t.Fatal("direct referent legacy source locator refresh failed")
	}
	legacyReferrers.Store(false)
	if legacyRequests.Load() != 1 {
		t.Fatal("referrer locator legacy source fallback did not run exactly once")
	}
	t.Log("PASS: stock ORAS discovers alternate-only referrers; direct pins after real process restart rewalk source pages and legacy fallback without persisting locator URLs")

	corrupt.Store(true)
	if code, _ := request(repo.Name, "blobs", crypt.Digest(payload)); code == 200 {
		t.Fatal("corrupt alternate served or admitted stale bytes")
	}
	bad := repo
	bad.Name = repo.Name + "-bad"
	create(bad)
	copyImage(bad.Name, "bad", true)
	if artifacts, e := db.Artifacts(ctx, identity, bad.Name, "", true); e != nil || len(artifacts) != 0 {
		t.Fatal("invalid alternate partially published a graph", e)
	}
	corrupt.Store(false)
	if code, data := request(repo.Name, "blobs", crypt.Digest(payload)); code != 200 || !bytes.Equal(data, payload) {
		t.Fatal("valid alternate did not recover after integrity failure")
	}
	t.Log("PASS: corrupt alternates neither serve stale bytes nor publish partial graph references; valid repair recovers")
	if _, e = db.Mutate(ctx, identity, "", "", "artifact.decision", func(tx pgx.Tx) (any, int, error) {
		v, e := store.Decide(ctx, tx, identity, repo.Name, "app/blobs/sha256:"+crypt.Digest(payload), crypt.Digest(payload), "denied")
		return v, 200, e
	}); e != nil {
		t.Fatal(e)
	}
	beforeDelivery := deliveries.Load()
	if code, _ := request(group.Name, "blobs", crypt.Digest(payload)); code != 403 {
		t.Fatalf("direct descriptor fallback lost explicit current digest denial: status=%d", code)
	}
	if deliveries.Load() != beforeDelivery {
		t.Fatal("denied member reached alternate source")
	}
	if e = db.Tx(ctx, identity, false, func(tx pgx.Tx) error {
		for _, table := range []string{"artifacts", "retrievals", "repositories", "events", "jobs"} {
			var data string
			if e := tx.QueryRow(ctx, `SELECT COALESCE(string_agg(to_jsonb(r)::text,''),'') FROM cratectl.`+table+` r`).Scan(&data); e != nil {
				return e
			}
			for _, secret := range []string{nonce, nonceAfter, "owned-descriptor-password", "owned-descriptor-origin", "/objects/payload?"} {
				if strings.Contains(data, secret) {
					return errors.New("descriptor locator or source credential entered normalized durable tenant data")
				}
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	t.Log("PASS: current digest policy blocks alternate requests; normalized metadata/cache/journal/jobs retain no descriptor query or source credential (original immutable manifest bytes remain exact)")
}
