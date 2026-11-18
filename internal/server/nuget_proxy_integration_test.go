//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testnet"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestNuGetProxyFlatContainerUsesCurrentPolicyAndImmutableArchives(t *testing.T) {
	s, schema, token, admin := schemaServer(t)
	s.PublicURL = "https://127.0.0.1:38443"
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	const name, id, version = "cratectl-nuget-proxy", "cratectl.proxy", "1.0.0"
	const base = "/cratectl-nuget-origin/"
	const native = "/nuget/" + name + "/"
	const flat = native + "flat/" + id + "/"
	const packageURL = flat + version + "/" + id + "." + version + ".nupkg"
	const manifestURL = flat + version + "/" + id + ".nuspec"
	data, manifest := nugetNupkgFixture(t, "Cratectl.Proxy", "1.0+owned")
	replacement, _ := nugetNupkgFixture(t, "Cratectl.Proxy", "1.0+changed")
	mismatch, _ := nugetNupkgFixture(t, "Cratectl.Other", "1.0.0")
	var requests atomic.Int64
	var changed atomic.Bool
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", "max-age=120")
		var body []byte
		switch strings.TrimSuffix(r.URL.Path, ".sha512") {
		case base + id + "/index.json":
			body = []byte(`{"versions":["2.0.0","1.0.0"]}`)
		case base + id + "/1.0.0/" + id + ".1.0.0.nupkg":
			body = data
			if changed.Load() {
				body = replacement
			}
		case base + id + "/2.0.0/" + id + ".2.0.0.nupkg":
			// An intact archive with the wrong identity is unusable.
			body = mismatch
		case base + id + "/3.0.0/" + id + ".3.0.0.nupkg":
			body = data
			if strings.HasSuffix(r.URL.Path, ".sha512") {
				body = mismatch
			}
		case base + "cratectl.empty/index.json":
			body = []byte(`{"versions":[]}`)
		case base + "cratectl.duplicate/index.json":
			body = []byte(`{"versions":["1.0.0","1.0.0"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".sha512") {
			body = []byte(strings.TrimPrefix(crypt.Integrity(body), "sha512-"))
		}
		_, _ = w.Write(body)
	})}}
	origin.Start()
	defer origin.Close()
	mavenRepositories(t, s, admin, store.Repository{Name: name, Format: "nuget", Mode: "proxy", Access: "restricted", RequireReview: true,
		Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + base, Networks: []string{"127.0.0.1/32"}},
			Cache: store.CacheSettings{FreshSeconds: 120, NegativeSeconds: 60, RequireChecksum: true}}})
	read := func(server *Server, credential, method, path string, status int, expected []byte, headers ...string) {
		t.Helper()
		w := nugetHTTP(t, server, credential, method, path, nil, "", headers...)
		if w.Code != status || expected != nil && !bytes.Equal(w.Body.Bytes(), expected) {
			t.Fatalf("%s %s returned %d, want %d with matching bytes: %.400s", method, path, w.Code, status, w.Body.String())
		}
	}
	read(s, token, "GET", native+"index.json", 200, []byte(`{"resources":[{"@id":"https://127.0.0.1:38443`+native+`flat/","@type":"PackageBaseAddress/3.0.0"}],"version":"3.0.0"}`))
	read(s, token, "GET", native+"query", 404, nil)
	ctx := context.Background()
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, schema.OwnerDSN, admin.Tenant, "cratectl-nuget-reader", "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	read(s, reader, "GET", flat+"index.json", 403, nil)
	if requests.Load() != 0 {
		t.Fatal("unauthorized requests reached the origin")
	}
	read(s, token, "GET", flat+"index.json", 404, nil)
	read(s, token, "GET", packageURL, 403, nil)
	path, digest := store.NuGetPath(id, version), crypt.Digest(data)
	decide := func(decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, name, path, digest, decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide("allowed")
	before := requests.Load()
	read(s, token, "GET", flat+"index.json", 200, []byte(`{"versions":["1.0.0"]}`))
	read(s, token, "GET", packageURL, 200, data)
	read(s, token, "GET", manifestURL, 200, manifest)
	read(s, token, "GET", packageURL, 206, data[1:8], "Range", "bytes=1-7")
	read(s, token, "HEAD", manifestURL, 200, []byte{})
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	read(restarted, token, "GET", packageURL, 200, data)
	if requests.Load() != before || before != 3 {
		t.Fatal("warm or derived manifest read contacted the origin", before, requests.Load())
	}
	decide("denied")
	read(s, token, "GET", flat+"index.json", 404, nil)
	read(s, token, "GET", manifestURL, 403, nil)
	decide("allowed")
	for _, invalid := range []struct{ version, failure string }{
		{"2.0.0", "upstream_nuget_coordinate_mismatch"}, {"3.0.0", "upstream_integrity_failure"},
	} {
		read(s, token, "GET", flat+invalid.version+"/"+id+"."+invalid.version+".nupkg", 502, nil)
		invalidPath := store.NuGetPath(id, invalid.version)
		state, err := s.DB.Retrieval(ctx, admin, name, invalidPath)
		if err != nil || state.State != "failed" || state.LastError != invalid.failure {
			t.Fatal("unexpected validation receipt", state.State, state.LastError, err)
		}
		if _, err := s.DB.ArtifactForPublication(ctx, admin, name, invalidPath); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("invalid archive created a reference", err)
		}
	}
	api := lifecycleHTTP(t, s, token)
	if w := api("PUT", "/api/v1/repositories/"+name+"/policy", map[string]bool{"require_review": false}, "cratectl-open-proxy"); w.Code != 200 {
		t.Fatal("disable repository review for the open-catalog regression", w.Code, w.Body.String())
	}
	read(s, token, "GET", flat+"index.json", 200, []byte(`{"versions":["1.0.0"]}`))
	read(s, token, "GET", native+"flat/cratectl.empty/index.json", 404, nil)
	read(s, token, "GET", native+"flat/cratectl.duplicate/index.json", 502, nil)
	changed.Store(true)
	read(s, token, "GET", packageURL, 502, nil, "Cache-Control", "no-cache")
	retained, err := s.DB.ArtifactForPublication(ctx, admin, name, path)
	if err != nil || retained.Digest != digest {
		t.Fatal("source replacement changed the retained coordinate", err)
	}
	read(s, token, "GET", flat+"index.json", 404, nil)
}

func TestNuGetProxyCatalogRefreshesWithoutFreshness(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cratectl-nuget-refresh/cratectl.refresh/index.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		if requests.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"versions":["2.0.0","1.0.0"]}`)
			return
		}
		_, _ = io.WriteString(w, `{"versions":["2.0.0"]}`)
	})}}
	origin.Start()
	defer origin.Close()
	mavenRepositories(t, s, admin, store.Repository{Name: "cratectl-nuget-refresh", Format: "nuget", Mode: "proxy", Settings: store.RepositorySettings{
		Upstream: &upstream.Config{URL: origin.URL + "/cratectl-nuget-refresh/", Networks: []string{"127.0.0.1/32"}},
		Cache:    store.CacheSettings{FreshSeconds: 120},
	}})
	for _, expected := range []string{`{"versions":["1.0.0","2.0.0"]}`, `{"versions":["2.0.0"]}`} {
		w := nugetHTTP(t, s, token, "GET", "/nuget/cratectl-nuget-refresh/flat/cratectl.refresh/index.json", nil, "")
		if w.Code != 200 || w.Body.String() != expected {
			t.Fatal("no-cache catalog did not serve the current normalized projection", w.Code, w.Body.String())
		}
	}
	if requests.Load() != 2 {
		t.Fatal("no-cache catalog reused an earlier validation", requests.Load())
	}
}
