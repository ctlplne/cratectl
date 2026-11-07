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

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/server"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testnet"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

const nativeOCIImage = "application/vnd.oci.image.manifest.v1+json"

func TestOCIStockORASSignedDeliveryAndGovernedPublication(t *testing.T) {
	if os.Getenv("CRATECTL_DSN") == "" || os.Getenv("CRATECTL_OWNER_DSN") == "" {
		t.Fatal("Runtime and owner DSNs required; integration never skips")
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
	if e = store.Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), "test-a", "oci-delivery", "admin", token, time.Now().Add(time.Hour)); e != nil {
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
	var currentQuery atomic.Value
	queryFor := func(value string) string {
		return "X-Registry-Proof=" + value + "&order=two&order=one&scope=owned%2Fblob"
	}
	currentQuery.Store(queryFor(nonce))
	config := []byte("{}")
	payload := bytes.Repeat([]byte("owned signed OCI delivery payload\n"), 64)
	configDigest, payloadDigest := crypt.Digest(config), crypt.Digest(payload)
	descriptor := func(data []byte, media string) map[string]any {
		return map[string]any{"mediaType": media, "digest": "sha256:" + crypt.Digest(data), "size": len(data)}
	}
	layer := descriptor(payload, "text/plain")
	layer["annotations"] = map[string]string{"org.opencontainers.image.title": "payload.txt"}
	document, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": nativeOCIImage, "artifactType": "application/vnd.cratectl.proof", "config": descriptor(config, "application/vnd.oci.empty.v1+json"), "layers": []any{layer}})
	var corrupt atomic.Bool
	var deliveries, exchanges atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "delivery" || password != "owned-delivery-password" || r.URL.RawQuery != currentQuery.Load().(string) || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" {
			t.Error("signed delivery query or credential authority changed")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60, stale-if-error=120")
		switch r.URL.Path {
		case "/objects/" + configDigest:
			w.Header().Set("ETag", `"`+configDigest+`"`)
			w.Write(config)
		case "/objects/" + payloadDigest:
			w.Header().Set("ETag", `"`+payloadDigest+`"`)
			if corrupt.Load() {
				w.Write(bytes.Repeat([]byte("x"), len(payload)))
			} else {
				w.Write(payload)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer cdn.Close()
	realm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "realm" || password != "owned-realm-password" || r.URL.Query().Get("scope") != "repository:app:pull" || r.URL.Query().Get("service") != "owned-registry" {
			t.Error("realm authority/scope changed")
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, `{"access_token":"owned-issued-registry-pull","expires_in":60}`)
	}))
	defer realm.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-issued-registry-pull" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="owned-registry",scope="repository:app:pull"`, realm.URL+"/token"))
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60, stale-if-error=120")
		if strings.HasPrefix(r.URL.Path, "/v2/app/manifests/") {
			w.Header().Set("ETag", `"owned-exact-root"`)
			w.Header().Set("Content-Type", nativeOCIImage)
			w.Header().Set("Docker-Content-Digest", "sha256:"+crypt.Digest(document))
			if r.Header.Get("If-None-Match") == `"owned-exact-root"` {
				w.WriteHeader(304)
				return
			}
			w.Write(document)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/app/blobs/sha256:") {
			digest := strings.TrimPrefix(r.URL.Path, "/v2/app/blobs/sha256:")
			w.Header().Set("Location", cdn.URL+"/objects/"+digest+"?"+currentQuery.Load().(string))
			w.WriteHeader(307)
			return
		}
		w.WriteHeader(404)
	}))
	defer origin.Close()
	objects, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	api := server.New(db, objects, "http://127.0.0.1:38443")
	api.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	api.UpstreamCredentials["test-a/realm"] = server.UpstreamCredential{Value: "realm:owned-realm-password", AllowedURL: realm.URL + "/token", Authentication: "basic"}
	api.UpstreamCredentials["test-a/delivery"] = server.UpstreamCredential{Value: "delivery:owned-delivery-password", AllowedURL: cdn.URL + "/objects/", Authentication: "basic"}
	base := store.Repository{Name: fmt.Sprintf("oci-delivery-%d", time.Now().UnixNano()), Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60, StaleSeconds: 120}, OCITokenEndpoint: &upstream.Config{URL: realm.URL + "/token", Networks: []string{"127.0.0.1/32"}, CredentialRef: "realm", Authentication: "basic"}, OCITokenService: "owned-registry", DownloadSources: []upstream.Config{{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "delivery", Authentication: "basic", AllowSignedQuery: true}}}}
	create := func(repo store.Repository) {
		t.Helper()
		if _, e := db.Mutate(ctx, identity, "", "", "repository.created", func(tx pgx.Tx) (any, int, error) { return repo, 201, store.CreateRepository(ctx, tx, identity, repo) }); e != nil {
			t.Fatal(e)
		}
	}
	create(base)
	group := store.Repository{Name: base.Name + "-group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{base.Name}}}
	create(group)
	listener, e := testnet.ListenOwned()
	if e != nil {
		t.Fatal("Owned native client port unavailable:", e)
	}
	live := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second}
	finished := make(chan error, 1)
	go func() { finished <- live.Serve(listener) }()
	defer func() {
		live.Close()
		if e := <-finished; !errors.Is(e, http.ErrServerClosed) {
			t.Error("Owned server termination:", e)
		}
	}()
	oras, e := filepath.Abs("../../.cache/bin/oras")
	if e != nil {
		t.Fatal(e)
	}
	private := retainedNativeDir(t)
	auth := filepath.Join(private, "registry.json")
	command := func(dir, input string, wantFailure bool, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, oras, args...)
		cmd.Env = nativeClientEnvironment()
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(input)
		out, e := cmd.CombinedOutput()
		retainNativeOutput(t, private, out)
		text := string(out)
		for _, value := range []string{token, nonce, nonceAfter, "owned-realm-password", "owned-delivery-password", "owned-issued-registry-pull"} {
			text = strings.ReplaceAll(text, value, "[REDACTED]")
		}
		if wantFailure {
			if e == nil {
				t.Fatal("Denied/corrupt native pull unexpectedly succeeded")
			}
			return
		}
		if e != nil {
			t.Fatalf("stock ORAS failed: %v: %s", e, text)
		}
	}
	versionCommand := exec.CommandContext(ctx, oras, "version")
	versionCommand.Env = nativeClientEnvironment()
	version, e := versionCommand.CombinedOutput()
	retainNativeOutput(t, private, version)
	if e != nil {
		t.Fatal("Stock ORAS required:", e)
	}
	t.Log(strings.TrimSpace(string(version)))
	command(private, token+"\n", false, "login", "--plain-http", "--registry-config", auth, "--username", "token", "--password-stdin", "127.0.0.1:38443")
	if e = os.Chmod(auth, 0600); e != nil {
		t.Fatal(e)
	}
	pull := func(repo, label string, wantFailure bool) {
		t.Helper()
		dir := filepath.Join(private, label)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		command(dir, "", wantFailure, "pull", "--plain-http", "--registry-config", auth, "127.0.0.1:38443/"+repo+"/app:v1")
		if !wantFailure {
			data, e := os.ReadFile(filepath.Join(dir, "payload.txt"))
			if e != nil || !bytes.Equal(data, payload) {
				t.Fatal("Native delivery bytes differ:", e)
			}
		}
	}
	pull(base.Name, "proxy", false)
	pull(group.Name, "group", false)
	if deliveries.Load() != 2 || exchanges.Load() != 1 {
		t.Fatalf("Fresh proxy/group cache repeated delivery: objects=%d exchanges=%d", deliveries.Load(), exchanges.Load())
	}
	t.Log("PASS: stock ORAS proxy/group pull exact signed-delivery graph with separated registry, realm and delivery credentials")
	member := "app/blobs/sha256:" + payloadDigest
	if _, e = db.Mutate(ctx, identity, "", "", "proxy.cache.invalidated", func(tx pgx.Tx) (any, int, error) {
		value, e := store.InvalidateRetrieval(ctx, tx, identity, base.Name, member)
		return value, 200, e
	}); e != nil {
		t.Fatal(e)
	}
	currentQuery.Store(queryFor(nonceAfter))
	pull(group.Name, "revalidated", false)
	if deliveries.Load() != 4 {
		t.Fatalf("Root 304 failed to renew signed deliveries: %d", deliveries.Load())
	}
	t.Log("PASS: root 304 renews dependencies through newly issued query URLs after member invalidation")
	assertNoReferences := func(repo string) {
		t.Helper()
		if e := db.Tx(ctx, identity, false, func(tx pgx.Tx) error {
			var n int
			e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.artifacts WHERE repository=$1`, repo).Scan(&n)
			if e == nil && n != 0 {
				return fmt.Errorf("rejected graph left %d references", n)
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	bad := base
	bad.Name = base.Name + "-corrupt"
	create(bad)
	corrupt.Store(true)
	pull(bad.Name, "corrupt", true)
	corrupt.Store(false)
	assertNoReferences(bad.Name)
	denied := base
	denied.Name = base.Name + "-query-denied"
	denied.Settings.DownloadSources = append([]upstream.Config(nil), base.Settings.DownloadSources...)
	denied.Settings.DownloadSources[0].AllowSignedQuery = false
	create(denied)
	before := deliveries.Load()
	pull(denied.Name, "query-denied", true)
	if deliveries.Load() != before {
		t.Fatal("Query denial contacted delivery")
	}
	assertNoReferences(denied.Name)
	t.Log("PASS: corrupt bytes and unapproved query use cannot partially publish an OCI graph")
	if _, e = db.Mutate(ctx, identity, "", "", "artifact.decision", func(tx pgx.Tx) (any, int, error) {
		value, e := store.Decide(ctx, tx, identity, base.Name, member, payloadDigest, "denied")
		return value, 200, e
	}); e != nil {
		t.Fatal(e)
	}
	pull(group.Name, "policy-denied", true)
	if deliveries.Load() != before {
		t.Fatal("Fresh policy denial bypassed into another delivery")
	}
	if e = db.Tx(ctx, identity, false, func(tx pgx.Tx) error {
		for _, table := range []string{"artifacts", "retrievals", "repositories", "events", "jobs"} {
			predicate := "repository=$1"
			switch table {
			case "repositories":
				predicate = "name=$1"
			case "events":
				predicate = "payload::jsonb->'data'->>'repository'=$1"
			case "jobs":
				predicate = "sequence IN(SELECT sequence FROM cratectl.events WHERE payload::jsonb->'data'->>'repository'=$1)"
			}
			var data string
			if e := tx.QueryRow(ctx, `SELECT COALESCE(string_agg(to_jsonb(r)::text,''),'') FROM cratectl.`+table+` r WHERE `+predicate, base.Name).Scan(&data); e != nil {
				return e
			}
			for _, value := range []string{nonce, nonceAfter, "X-Registry-Proof", "owned-realm-password", "owned-delivery-password", "owned-issued-registry-pull"} {
				if strings.Contains(data, value) {
					return errors.New("ephemeral delivery credential entered durable repository data")
				}
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	t.Log("PASS: current digest denial still governs cached group pulls; ephemeral query and credentials absent from durable repository/cache/journal/job data")
}
