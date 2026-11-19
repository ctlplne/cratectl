//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
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

func TestNuGetGroupKeepsPackageAuthorityAcrossPolicyAndUpstreamChanges(t *testing.T) {
	s, schema, token, admin := schemaServer(t)
	s.PublicURL = "https://127.0.0.1:38443"
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	ctx := context.Background()
	const id, display = "cratectl.group", "Cratectl.Group"
	const group, preferred, lower, claimed = "cratectl-nuget-group", "cratectl-nuget-preferred", "cratectl-nuget-lower", "cratectl-nuget-owned"
	const name, base = "cratectl-nuget-group-reader", "/cratectl-nuget-group-origin/"
	const flat = "/nuget/" + group + "/flat/" + id + "/"
	const one = "1.0.0/" + id + ".1.0.0.nupkg"
	const two = "2.0.0/" + id + ".2.0.0.nupkg"
	const nuspec = "1.0.0/" + id + ".nuspec"
	up, upNuspec := nugetNupkgFixture(t, display, "1.0+upstream")
	down, downNuspec := nugetNupkgFixture(t, display, "1.0+hosted")
	downTwo, _ := nugetNupkgFixture(t, display, "2.0.0")
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var state atomic.Int32
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", "max-age=120")
		switch state.Load() {
		case 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body []byte
		switch r.URL.Path {
		case base + id + "/index.json":
			body = []byte(`{"versions":["1.0.0"]}`)
		case base + id + "/" + one:
			body = up
		case base + id + "/" + one + ".sha512":
			body = []byte(strings.TrimPrefix(crypt.Integrity(up), "sha512-"))
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	})}}
	origin.Start()
	defer origin.Close()
	members := []string{preferred, lower}
	mavenRepositories(t, s, admin,
		store.Repository{Name: preferred, Format: "nuget", Mode: "proxy", Access: "restricted", Settings: store.RepositorySettings{
			Upstream: &upstream.Config{URL: origin.URL + base, Networks: []string{"127.0.0.1/32"}},
			Cache:    store.CacheSettings{FreshSeconds: 120, NegativeSeconds: 30, RequireChecksum: true},
		}},
		store.Repository{Name: lower, Format: "nuget"},
		store.Repository{Name: group, Format: "nuget", Mode: "group", RequireReview: true, Settings: store.RepositorySettings{Members: members}},
		store.Repository{Name: claimed, Format: "nuget", Mode: "group", Settings: store.RepositorySettings{
			Members: members, NamespaceOwners: map[string]string{id + "/": lower},
		}})
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, schema.OwnerDSN, admin.Tenant, name, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	api := lifecycleHTTP(t, s, token)
	grant := func(enable bool, key string) {
		t.Helper()
		if w := api(http.MethodPut, "/api/v1/repositories/"+preferred+"/grants", map[string]any{"actor": name, "read": enable}, key); w.Code != 200 {
			t.Fatal("update preferred grant", w.Code, w.Body.String())
		}
	}
	decide := func(repo, version, decision string, data []byte) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, store.NuGetPath(id, version), crypt.Digest(data), decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, release := range []struct {
		version string
		data    []byte
	}{{"1.0.0", down}, {"2.0.0", downTwo}} {
		body, kind := nugetMultipart(t, release.data, 0)
		w := nugetHTTP(t, s, token, "PUT", "/nuget/"+lower+"/api/v2/package", body, kind)
		if w.Code != 201 {
			t.Fatal("publish lower hosted fixture", w.Code, w.Body.String())
		}
		decide(lower, release.version, "allowed", release.data)
	}
	check := func(path string, status int, expected []byte, source string, headers ...string) {
		t.Helper()
		w := nugetHTTP(t, s, reader, "GET", path, nil, "", headers...)
		if w.Code != status || expected != nil && !bytes.Equal(w.Body.Bytes(), expected) || source != "" && w.Header().Get("X-Cratectl-Repository") != source {
			t.Fatalf("%s returned %d, expected %d from %s: %.400s", path, w.Code, status, source, w.Body.String())
		}
	}
	check(flat+"index.json", 403, nil, "")
	check(flat+one, 403, nil, "")
	check("/nuget/"+claimed+"/flat/"+id+"/"+one, 200, down, lower)
	if requests.Load() != 0 {
		t.Fatal("ungranted preferred source or explicit owner consulted origin")
	}
	grant(true, "cratectl-nuget-group-grant")
	check(flat+"index.json", 200, []byte(`{"versions":["1.0.0","2.0.0"]}`), "")
	check(flat+one, 200, down, lower)
	check(flat+nuspec, 200, downNuspec, lower)
	if requests.Load() != 1 {
		t.Fatal("warm preferred absence needed only its single native catalog request", requests.Load())
	}
	state.Store(2)
	check(flat+"index.json", 502, nil, "", "Cache-Control", "no-cache")
	check(flat+one, 502, nil, "")
	state.Store(1)
	check(flat+"index.json", 404, nil, "", "Cache-Control", "no-cache")
	check(flat+one, 403, nil, "")
	check(flat+two, 404, nil, "")
	decide(preferred, "1.0.0", "allowed", up)
	check(flat+"index.json", 200, []byte(`{"versions":["1.0.0"]}`), "")
	check(flat+one, 200, up, preferred)
	check(flat+nuspec, 200, upNuspec, preferred)
	decide(preferred, "1.0.0", "denied", up)
	check(flat+"index.json", 404, nil, "")
	check(flat+one, 403, nil, "")
	state.Store(0)
	check(flat+"index.json", 404, nil, "", "Cache-Control", "no-cache")
	check(flat+one, 404, nil, "")
	check(flat+two, 404, nil, "")
	grant(false, "cratectl-nuget-group-revoke")
	check(flat+"index.json", 403, nil, "")
	check("/nuget/"+claimed+"/flat/"+id+"/"+two, 200, downTwo, lower)
}
