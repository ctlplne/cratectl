// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestOCIApprovedDeliveryKeepsCredentialsAtTheirAuthority(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, _ := r.BasicAuth()
		if user != "delivery" || password != "owned-delivery-password" || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" {
			t.Error("delivery credential authority or header boundary changed")
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, "owned exact delivered bytes")
	}))
	defer cdn.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-origin-token" {
			t.Error("origin credential missing")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Location", cdn.URL+"/objects/layer")
		w.WriteHeader(307)
	}))
	defer origin.Close()
	server := New(nil, nil, "")
	server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	server.UpstreamCredentials["test-a/origin"] = UpstreamCredential{Value: "owned-origin-token", AllowedURL: origin.URL + "/v2/"}
	server.UpstreamCredentials["test-a/delivery"] = UpstreamCredential{Value: "delivery:owned-delivery-password", AllowedURL: cdn.URL + "/objects/", Authentication: "basic"}
	repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "origin"}, DownloadSources: []upstream.Config{{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "delivery", Authentication: "basic"}}}}
	client, e := server.newOCIRegistryClient(store.Identity{Tenant: "test-a"}, repo, "app")
	if e != nil {
		t.Fatal(e)
	}
	defer client.close()
	response, e := client.get(context.Background(), "app/blobs/sha256:fixture", nil, nil)
	if e != nil {
		t.Fatalf("approved delivery rejected: %v", e)
	}
	defer response.Body.Close()
	data, e := io.ReadAll(response.Body)
	if e != nil || response.StatusCode != 200 || string(data) != "owned exact delivered bytes" {
		t.Fatalf("approved delivery failed: status=%d error=%v", response.StatusCode, e)
	}
}

func TestOCISignedDeliveryRedirectBoundaries(t *testing.T) {
	const query = "X-Amz-Credential=owned%2Fscope&X-Amz-Signature=opaque-proof&b=2&a=1&a=2"
	for _, mode := range []string{"valid", "query-denied", "foreign", "path", "traversal", "userinfo", "loop", "second-foreign", "duplicate-location", "network", "ceiling", "malformed-query", "malformed-location", "large-query", "budget-disabled", "budget-pairs", "budget-bytes"} {
		t.Run(mode, func(t *testing.T) {
			var hits, foreignHits atomic.Int32
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
			defer foreign.Close()
			cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Header.Get("Authorization") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" {
					t.Error("origin authority reached signed delivery")
				}
				if r.URL.RawQuery != query {
					t.Error("signed query bytes/order changed")
				}
				switch mode {
				case "loop":
					w.Header().Set("Location", "/objects/layer?"+query)
					w.WriteHeader(307)
					return
				case "second-foreign":
					w.Header().Set("Location", foreign.URL+"/objects/layer?"+query)
					w.WriteHeader(302)
					return
				}
				io.WriteString(w, "owned signed bytes")
			}))
			defer cdn.Close()
			location := cdn.URL + "/objects/layer?" + query
			switch mode {
			case "foreign":
				location = foreign.URL + "/objects/layer?" + query
			case "path":
				location = cdn.URL + "/private/layer?" + query
			case "traversal":
				location = cdn.URL + "/objects/%2e%2e/private?" + query
			case "userinfo":
				location = strings.Replace(location, "http://", "http://owned@", 1)
			case "ceiling":
				location = strings.Replace(location, "127.0.0.1", "127.0.0.2", 1)
			case "malformed-query":
				location = cdn.URL + "/objects/layer?signature=%ZZ"
			case "malformed-location":
				location = cdn.URL + "/objects/bad%ZZ?signature=owned-opaque"
			case "large-query":
				location = cdn.URL + "/objects/layer?signature=" + strings.Repeat("q", 9000)
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer owned-origin-token" {
					t.Error("origin credential lost")
				}
				w.Header().Set("Location", location)
				if mode == "duplicate-location" {
					w.Header().Add("Location", foreign.URL+"/sink")
				}
				w.WriteHeader(307)
			}))
			defer origin.Close()
			server := New(nil, nil, "")
			server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			server.UpstreamCredentials["test-a/origin"] = UpstreamCredential{Value: "owned-origin-token", AllowedURL: origin.URL + "/v2/"}
			delivery := upstream.Config{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, AllowSignedQuery: mode != "query-denied"}
			if mode == "network" {
				delivery.Networks = []string{"192.0.2.0/24"}
			}
			if mode == "ceiling" {
				delivery.URL = strings.Replace(delivery.URL, "127.0.0.1", "127.0.0.2", 1)
				delivery.Networks = []string{"127.0.0.0/8"}
			}
			if mode == "budget-disabled" {
				if e := server.ConfigureOCIDelivery(0, upstream.DefaultRegistryDeliveryLimits()); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "budget-pairs" {
				limits := upstream.DefaultRegistryDeliveryLimits()
				limits.QueryPairs = 1
				if e := server.ConfigureOCIDelivery(5, limits); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "budget-bytes" {
				limits := upstream.RegistryDeliveryLimits{URLBytes: 80, QueryBytes: 64, QueryPairs: 64}
				if e := server.ConfigureOCIDelivery(5, limits); e != nil {
					t.Fatal(e)
				}
			}
			repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "origin"}, DownloadSources: []upstream.Config{delivery}}}
			client, e := server.newOCIRegistryClient(store.Identity{Tenant: "test-a"}, repo, "app")
			if e != nil {
				t.Fatal(e)
			}
			defer client.close()
			response, e := client.get(context.Background(), "app/blobs/sha256:fixture", nil, nil)
			if response != nil {
				response.Body.Close()
			}
			if mode == "valid" {
				if e != nil || response.StatusCode != 200 || hits.Load() != 1 {
					t.Fatalf("approved signed delivery failed: %v hits=%d", e, hits.Load())
				}
			} else {
				if e == nil {
					t.Fatal("unapproved delivery accepted")
				}
				if strings.Contains(e.Error(), query) || strings.Contains(e.Error(), "signature=") {
					t.Fatal("signed URI exposed in returned error")
				}
				if mode != "loop" && mode != "second-foreign" && hits.Load() != 0 {
					t.Fatalf("rejected destination was contacted: %d", hits.Load())
				}
			}
			if hits.Load() > 5 || foreignHits.Load() != 0 {
				t.Fatalf("redirect budget/authority escaped: approved=%d foreign=%d", hits.Load(), foreignHits.Load())
			}
		})
	}
}

func TestOCIMoreSpecificDeliveryCannotUseBroaderOriginCredentials(t *testing.T) {
	var delivered atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/objects/layer" {
			delivered.Add(1)
			return
		}
		w.Header().Set("Location", "/objects/layer?signature=owned-opaque")
		w.WriteHeader(307)
	}))
	defer origin.Close()
	server := New(nil, nil, "")
	server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	server.UpstreamCredentials["test-a/origin"] = UpstreamCredential{Value: "owned-origin-token", AllowedURL: origin.URL + "/"}
	repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "origin", AllowSignedQuery: true}, DownloadSources: []upstream.Config{{URL: origin.URL + "/objects/", Networks: []string{"127.0.0.1/32"}}}}}
	client, e := server.newOCIRegistryClient(store.Identity{Tenant: "test-a"}, repo, "app")
	if e != nil {
		t.Fatal(e)
	}
	defer client.close()
	if _, e = client.get(context.Background(), "app/blobs/sha256:fixture", nil, nil); e == nil || delivered.Load() != 0 {
		t.Fatalf("query rejection fell through to broader credentials: %v hits=%d", e, delivered.Load())
	}
}

func TestOCIDeliveryRejectsDowngradeBeforeRequest(t *testing.T) {
	request, _ := http.NewRequest("GET", "https://registry.example/v2/app/blobs/sha256:fixture", nil)
	response := &http.Response{Request: request, Header: http.Header{"Location": {"http://127.0.0.1/objects/layer?signature=owned"}}}
	if _, e := ociDeliveryLocation(response, 0, 5, 16384); !errors.Is(e, upstream.ErrRedirect) {
		t.Fatalf("TLS downgrade accepted: %v", e)
	}
}

func TestOCIRealmBearerDoesNotReachDelivery(t *testing.T) {
	var exchanges, deliveries atomic.Int32
	realm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if r.URL.Query().Get("scope") != "repository:app:pull" || r.URL.Query().Get("service") != "owned-registry" {
			t.Error("token scope changed")
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, `{"token":"owned-issued-pull-token","expires_in":60}`)
	}))
	defer realm.Close()
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("issued registry bearer reached delivery")
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://foreign.invalid/token",service="foreign"`)
		w.WriteHeader(401)
	}))
	defer cdn.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-issued-pull-token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="owned-registry",scope="repository:app:pull"`, realm.URL+"/token"))
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Location", cdn.URL+"/objects/layer?signature=owned-opaque")
		w.WriteHeader(307)
	}))
	defer origin.Close()
	server := New(nil, nil, "")
	server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, OCITokenEndpoint: &upstream.Config{URL: realm.URL + "/token", Networks: []string{"127.0.0.1/32"}}, OCITokenService: "owned-registry", DownloadSources: []upstream.Config{{URL: cdn.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, AllowSignedQuery: true}}}}
	client, e := server.newOCIRegistryClient(store.Identity{Tenant: "test-a"}, repo, "app")
	if e != nil {
		t.Fatal(e)
	}
	defer client.close()
	response, e := client.get(context.Background(), "app/blobs/sha256:fixture", nil, nil)
	if response != nil {
		response.Body.Close()
	}
	if e != nil || response.StatusCode != 401 || exchanges.Load() != 1 || deliveries.Load() != 1 {
		t.Fatalf("delivery initiated another token exchange: %v exchanges=%d deliveries=%d", e, exchanges.Load(), deliveries.Load())
	}
}
