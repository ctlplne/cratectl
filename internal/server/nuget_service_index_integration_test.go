//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testnet"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestNuGetServiceIndexBindsApprovedPackageAuthorityAndSeparateCredentials(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	const repo = "cratectl-nuget-service-index"
	const indexPath, approvedPath = "/cratectl-nuget-index/v3/index.json", "/cratectl-nuget-files/"
	const id, relative = "cratectl.service", "cratectl.service/1.0.0/cratectl.service.1.0.0.nupkg"
	const flat = "/nuget/" + repo + "/flat/"
	archive, manifest := nugetNupkgFixture(t, "Cratectl.Service", "1.0.0")
	indexSecret, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	fileSecret, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	var moved atomic.Bool
	var indexRequests, fileRequests, refusedRequests atomic.Int64
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=120")
		var data []byte
		switch r.URL.Path {
		case indexPath:
			indexRequests.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+indexSecret {
				refusedRequests.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			address := base + approvedPath
			if moved.Load() {
				address = base + "/cratectl-nuget-new-files/"
			}
			data = fmt.Appendf(nil, `{"version":"3.0.0","resources":[{"@id":%q,"@type":["PackageBaseAddress/3.0.0"],"comment":"owned"}]}`, address)
		case approvedPath + id + "/index.json", approvedPath + relative, approvedPath + relative + ".sha512":
			fileRequests.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+fileSecret {
				refusedRequests.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			data = archive
			if strings.HasSuffix(r.URL.Path, ".sha512") {
				data = []byte(strings.TrimPrefix(crypt.Integrity(archive), "sha512-"))
			} else if strings.HasSuffix(r.URL.Path, "/index.json") {
				data = []byte(`{"versions":["1.0.0"]}`)
			}
		default:
			refusedRequests.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	})}}
	origin.Start()
	defer origin.Close()
	networks := []string{"127.0.0.1/32"}
	s.UpstreamCredentials[admin.Tenant+"/cratectl-index"] = UpstreamCredential{Value: indexSecret, AllowedURL: base + indexPath}
	s.UpstreamCredentials[admin.Tenant+"/cratectl-files"] = UpstreamCredential{Value: fileSecret, AllowedURL: base + approvedPath}
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "nuget", Mode: "proxy", Settings: store.RepositorySettings{
		NuGetServiceIndex: true,
		Upstream:          &upstream.Config{URL: base + indexPath, Networks: networks, CredentialRef: "cratectl-index"},
		DownloadSources:   []upstream.Config{{URL: base + approvedPath, Networks: networks, CredentialRef: "cratectl-files"}},
		Cache:             store.CacheSettings{FreshSeconds: 120, RequireChecksum: true},
	}})
	for _, item := range []struct {
		path string
		data []byte
	}{{id + "/index.json", []byte(`{"versions":["1.0.0"]}`)}, {relative, archive}, {id + "/1.0.0/" + id + ".nuspec", manifest}} {
		w := nugetHTTP(t, s, token, "GET", flat+item.path, nil, "")
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), item.data) {
			t.Fatal("service index did not authorize exact scoped content", item.path, w.Code)
		}
	}
	if indexRequests.Load() != 2 || fileRequests.Load() != 3 || refusedRequests.Load() != 0 {
		t.Fatal("unexpected discovery and download requests", indexRequests.Load(), fileRequests.Load(), refusedRequests.Load())
	}
	moved.Store(true)
	w := nugetHTTP(t, s, token, "GET", flat+relative, nil, "", "Cache-Control", "no-cache")
	if w.Code != 502 || indexRequests.Load() != 3 || fileRequests.Load() != 3 || refusedRequests.Load() != 0 {
		t.Fatal("a discovered authority change was not fenced before any content request", w.Code, indexRequests.Load(), fileRequests.Load())
	}
	ctx := context.Background()
	state, err := s.DB.Retrieval(ctx, admin, repo, store.NuGetPath(id, "1.0.0"))
	if err != nil || state.LastError != "upstream_nuget_service_index_invalid" {
		t.Fatal("invalid service index did not record a durable retrieval outcome", state.LastError, err)
	}
	moved.Store(false)
	w = nugetHTTP(t, s, token, "GET", flat+relative, nil, "", "Cache-Control", "no-cache")
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), archive) || refusedRequests.Load() != 0 {
		t.Fatal("restored service-index authority did not recover exact content", w.Code)
	}
}
