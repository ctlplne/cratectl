//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package conformance

import (
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
	"sort"
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

func TestOCIStockDiscoveryPagesFallbackAndAtomicity(t *testing.T) {
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
	if e = store.Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), "test-a", "oci-discovery", "admin", token, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	identity, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	config := []byte("{}")
	configDigest := crypt.Digest(config)
	makeManifest := func(label, kind string, subject map[string]any) []byte {
		document := map[string]any{"schemaVersion": 2, "mediaType": nativeOCIImage, "config": map[string]any{"mediaType": "application/vnd.example.config", "digest": "sha256:" + configDigest, "size": len(config)}, "layers": []any{}, "annotations": map[string]string{"org.example.label": label}}
		if subject != nil {
			document["subject"] = subject
			document["artifactType"] = kind
		}
		raw, _ := json.Marshal(document)
		return raw
	}
	parent := makeManifest("parent", "", nil)
	parentDigest := "sha256:" + crypt.Digest(parent)
	subject := map[string]any{"mediaType": nativeOCIImage, "digest": parentDigest, "size": len(parent)}
	descriptors := []map[string]any{}
	documents := map[string][]byte{parentDigest: parent}
	expected := []string{}
	for n, label := range []string{"sbom-one", "signature", "sbom-two"} {
		kind := "application/vnd.example.sbom"
		if n == 1 {
			kind = "application/vnd.example.signature"
		}
		raw := makeManifest(label, kind, subject)
		digest := "sha256:" + crypt.Digest(raw)
		documents[digest] = raw
		expected = append(expected, digest)
		descriptors = append(descriptors, map[string]any{"mediaType": nativeOCIImage, "digest": digest, "size": len(raw), "artifactType": kind})
	}
	index := func(entries []map[string]any) []byte {
		data, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries})
		return data
	}
	var fallback, failPage atomic.Bool
	var pageHits, conditionalCatalog atomic.Int32
	var refStatus, fallbackStatus, fallbackHits atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageHits.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "pages" || password != "owned-page-password" || r.URL.RawQuery != "signature=owned%2Fpage&cursor=two" || r.Header.Get("Referer") != "" {
			t.Error("signed page authority/query changed")
			w.WriteHeader(403)
			return
		}
		if failPage.Load() {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write(index(descriptors[1:]))
	}))
	defer cdn.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-discovery-origin" {
			t.Error("origin credential missing")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		switch r.URL.Path {
		case "/v2/app/referrers/" + parentDigest:
			if code := refStatus.Load(); code != 0 {
				w.WriteHeader(int(code))
				return
			}
			if fallback.Load() {
				w.WriteHeader(404)
				return
			}
			if r.Header.Get("If-None-Match") != "" {
				conditionalCatalog.Add(1)
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"first-page-only"`)
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Header().Set("Link", fmt.Sprintf(`<?cursor=previous>; rel="prev", <%s/pages/referrers?signature=owned%%2Fpage&cursor=two>; rel="next"; title="two, three"`, cdn.URL))
			w.Write(index(descriptors[:1]))
			return
		case "/v2/app/tags/list":
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("cursor") == "two" {
				io.WriteString(w, `{"name":"app","tags":["a","z"]}`)
				return
			}
			w.Header().Set("Link", `<?cursor=two>; rel=next`)
			io.WriteString(w, `{"name":"app","tags":["A"]}`)
			return
		case "/v2/app/blobs/sha256:" + configDigest:
			w.Write(config)
			return
		case "/v2/app/manifests/" + strings.Replace(parentDigest, ":", "-", 1):
			fallbackHits.Add(1)
			if code := fallbackStatus.Load(); code != 0 {
				w.WriteHeader(int(code))
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Write(index(descriptors))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/app/manifests/") {
			ref := strings.TrimPrefix(r.URL.Path, "/v2/app/manifests/")
			data, ok := documents[ref]
			if ref == "A" || ref == "a" || ref == "z" {
				data, ok = parent, true
			}
			if ok {
				w.Header().Set("Content-Type", nativeOCIImage)
				w.Write(data)
				return
			}
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
	api.OCIPageSize = 1
	api.UpstreamCredentials["test-a/discovery-origin"] = server.UpstreamCredential{Value: "owned-discovery-origin", AllowedURL: origin.URL + "/v2/"}
	api.UpstreamCredentials["test-a/discovery-pages"] = server.UpstreamCredential{Value: "pages:owned-page-password", AllowedURL: cdn.URL + "/pages/", Authentication: "basic"}
	repo := store.Repository{Name: fmt.Sprintf("oci-pages-%d", time.Now().UnixNano()), Format: "oci", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "discovery-origin"}, DownloadSources: []upstream.Config{{URL: cdn.URL + "/pages/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "discovery-pages", Authentication: "basic", AllowSignedQuery: true}}, Cache: store.CacheSettings{FreshSeconds: 60, StaleSeconds: 120}}}
	create := func(value store.Repository) {
		t.Helper()
		if _, e := db.Mutate(ctx, identity, "", "", "repository.created", func(tx pgx.Tx) (any, int, error) { return value, 201, store.CreateRepository(ctx, tx, identity, value) }); e != nil {
			t.Fatal(e)
		}
	}
	create(repo)
	group := store.Repository{Name: repo.Name + "-group", Format: "oci", Mode: "group", Settings: store.RepositorySettings{Members: []string{repo.Name}}}
	create(group)
	listener, e := testnet.ListenOwned()
	if e != nil {
		t.Fatal(e)
	}
	live := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second}
	finished := make(chan error, 1)
	go func() { finished <- live.Serve(listener) }()
	defer func() { live.Close(); <-finished }()
	private := retainedNativeDir(t)
	auth := filepath.Join(private, "registry.json")
	oras, e := filepath.Abs("../../.cache/bin/oras")
	if e != nil {
		t.Fatal(e)
	}
	run := func(input string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, oras, args...)
		command.Env = nativeClientEnvironment()
		command.Dir = private
		command.Stdin = strings.NewReader(input)
		out, e := command.CombinedOutput()
		retainNativeOutput(t, private, out)
		if e != nil {
			t.Fatalf("stock discovery failed: %v %s", e, strings.ReplaceAll(string(out), token, "[REDACTED]"))
		}
		return out
	}
	run(token+"\n", "login", "--plain-http", "--registry-config", auth, "--username", "token", "--password-stdin", "127.0.0.1:38443")
	if e = os.Chmod(auth, 0600); e != nil {
		t.Fatal(e)
	}
	discover := func(name string) []string {
		t.Helper()
		raw := run("", "discover", "--plain-http", "--registry-config", auth, "--distribution-spec", "v1.1-referrers-api", "--depth", "1", "--format", "json", "127.0.0.1:38443/"+name+"/app@"+parentDigest)
		var data struct {
			Referrers []struct {
				Digest string `json:"digest"`
			} `json:"referrers"`
		}
		if e := json.Unmarshal(raw, &data); e != nil {
			t.Fatal(e)
		}
		result := []string{}
		for _, entry := range data.Referrers {
			result = append(result, entry.Digest)
		}
		sort.Strings(result)
		return result
	}
	sort.Strings(expected)
	if got := discover(group.Name); strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("native client missed referrer pages: %v", got)
	}
	if pageHits.Load() != 1 {
		t.Fatalf("complete upstream page cache not retained: %d", pageHits.Load())
	}
	tags := run("", "repo", "tags", "--plain-http", "--registry-config", auth, "127.0.0.1:38443/"+group.Name+"/app")
	if strings.Join(strings.Fields(string(tags)), ",") != "A,a,z" {
		t.Fatalf("native tags failed pagination/order: %s", tags)
	}
	t.Log("PASS: stock ORAS traverses governed downstream referrer/tag pages after complete opaque/signed upstream walks")
	request := func(path string, headers http.Header) (int, []byte, http.Header) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:38443"+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Header = headers.Clone()
		r.Header.Set("Authorization", "Bearer "+token)
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, data, response.Header
	}
	refPath := "/v2/" + group.Name + "/app/referrers/" + parentDigest
	code, raw, h := request(refPath+"?n=1&artifactType=application%2Fvnd.example.sbom", http.Header{})
	if code != 200 || !strings.Contains(h.Get("Link"), "artifactType=") || h.Get("OCI-Filters-Applied") != "artifactType" {
		t.Fatalf("filtered next Link lost context: %d %s", code, raw)
	}
	if code, _, _ := request(refPath+"?n=1&artifactType=application%2Fvnd.example.sbom", http.Header{"If-None-Match": {h.Get("ETag")}}); code != 304 {
		t.Fatal("page validators failed")
	}
	for _, query := range []string{"n=0", "n=1&last=sha256:" + strings.Repeat("f", 64)} {
		code, data, h := request(refPath+"?"+query, http.Header{})
		var value struct {
			Manifests []any `json:"manifests"`
		}
		json.Unmarshal(data, &value)
		if code != 200 || len(value.Manifests) != 0 || h.Get("Link") != "" {
			t.Fatal("zero/end page failed")
		}
	}

	request(refPath, http.Header{"Cache-Control": {"no-cache"}})
	if conditionalCatalog.Load() != 0 || pageHits.Load() != 2 {
		t.Fatal("first-page validator concealed a fresh full walk")
	}
	t.Log("PASS: filter context, zero pages and conditional downstream representations; refresh never treats a first-page ETag as a full catalog validator")
	bad := repo
	bad.Name = repo.Name + "-bad"
	create(bad)
	failPage.Store(true)
	code, _, _ = request("/v2/"+bad.Name+"/app/referrers/"+parentDigest, http.Header{})
	failPage.Store(false)
	if code == 200 {
		t.Fatal("later-page failure returned a partial success")
	}
	if artifacts, e := db.Artifacts(ctx, identity, bad.Name, "", true); e != nil || len(artifacts) != 0 {
		t.Fatalf("failed page left partial graph references: %d %v", len(artifacts), e)
	}
	t.Log("PASS: later-page source failure cannot publish a partial referrer catalog or graph")
	fallback.Store(true)
	legacy := repo
	legacy.Name = repo.Name + "-legacy"
	create(legacy)
	if got := discover(legacy.Name); strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("legacy referrers-tag fallback lost manifests: %v", got)
	}
	fallback.Store(false)
	t.Log("PASS: stock ORAS discovers governed proxy referrers through the legacy sha256-subject tag after API 404")
	beforeFallback := fallbackHits.Load()
	refStatus.Store(403)
	forbidden := repo
	forbidden.Name = repo.Name + "-forbidden"
	create(forbidden)
	code, _, _ = request("/v2/"+forbidden.Name+"/app/referrers/"+parentDigest, http.Header{})
	refStatus.Store(0)
	if code == 200 || fallbackHits.Load() != beforeFallback {
		t.Fatal("source authorization failure became an empty or fallback success")
	}
	fallback.Store(true)
	fallbackStatus.Store(404)
	empty := repo
	empty.Name = repo.Name + "-empty"
	create(empty)
	if got := discover(empty.Name); len(got) != 0 {
		t.Fatal("missing legacy referrers index was not empty")
	}
	fallback.Store(false)
	fallbackStatus.Store(0)
	if _, e = db.Mutate(ctx, identity, "", "", "artifact.decision", func(tx pgx.Tx) (any, int, error) {
		value, e := store.Decide(ctx, tx, identity, empty.Name, "app/manifests/"+parentDigest, strings.TrimPrefix(parentDigest, "sha256:"), "denied")
		return value, 200, e
	}); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := request("/v2/"+empty.Name+"/app/referrers/"+parentDigest+"?n=0", http.Header{}); code != 403 {
		t.Fatal("empty fallback page bypassed known subject denial")
	}
	t.Log("PASS: fallback requires API 404; missing fallback is empty and still subject to current subject policy")
	denied := expected[0]
	if _, e = db.Mutate(ctx, identity, "", "", "artifact.decision", func(tx pgx.Tx) (any, int, error) {
		value, e := store.Decide(ctx, tx, identity, repo.Name, "app/manifests/"+denied, strings.TrimPrefix(denied, "sha256:"), "denied")
		return value, 200, e
	}); e != nil {
		t.Fatal(e)
	}
	got := discover(group.Name)
	if len(got) != 2 || strings.Contains(strings.Join(got, ","), denied) {
		t.Fatal("current referrer denial bypassed in a later page")
	}
	if _, e = db.Mutate(ctx, identity, "", "", "artifact.decision", func(tx pgx.Tx) (any, int, error) {
		value, e := store.Decide(ctx, tx, identity, repo.Name, "app/manifests/"+parentDigest, strings.TrimPrefix(parentDigest, "sha256:"), "denied")
		return value, 200, e
	}); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := request(refPath+"?n=1&last="+expected[0], http.Header{}); code != 403 {
		t.Fatal("page marker bypassed subject denial")
	}
	t.Log("PASS: each native page rechecks current source/subject/referrer policy")
	if e = db.Tx(ctx, identity, false, func(tx pgx.Tx) error {
		for _, table := range []string{"artifacts", "retrievals", "repositories", "events", "jobs"} {
			var data string
			if e := tx.QueryRow(ctx, `SELECT COALESCE(string_agg(to_jsonb(r)::text,''),'') FROM cratectl.`+table+` r`).Scan(&data); e != nil {
				return e
			}
			for _, value := range []string{"signature=owned", "owned/page", "cursor=two", "owned-page-password", "owned-discovery-origin"} {
				if strings.Contains(data, value) {
					return errors.New("ephemeral discovery credential entered durable tenant data")
				}
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	t.Log("PASS: opaque/signed cursors and page credentials are absent from durable tenant data")
}
