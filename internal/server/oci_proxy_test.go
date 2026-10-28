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
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestOCIChallengeAndCredentialAuthority(t *testing.T) {
	for _, attack := range []string{"valid", "realm", "service", "scope", "duplicate", "token-redirect"} {
		t.Run(attack, func(t *testing.T) {
			var exchanges, requests atomic.Int32
			realm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				exchanges.Add(1)
				user, password, _ := r.BasicAuth()
				if r.URL.Path != "/token" || user != "owned-user" || password != "owned-realm-password" || r.URL.Query().Get("service") != "owned-registry" || r.URL.Query().Get("scope") != "repository:sample:pull" {
					t.Error("token credential/destination/scope crossed authority")
					w.WriteHeader(403)
					return
				}
				if attack == "token-redirect" {
					w.Header().Set("Location", "/token/escape")
					w.WriteHeader(302)
					return
				}
				io.WriteString(w, `{"token":"owned-issued-bearer","expires_in":60}`)
			}))
			defer realm.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if strings.Contains(r.Header.Get("Authorization"), "owned-realm-password") {
					t.Error("realm credential leaked to origin")
				}
				if r.Header.Get("Authorization") == "Bearer owned-issued-bearer" {
					io.WriteString(w, "exact registry response")
					return
				}
				endpoint, service, scope := realm.URL+"/token", "owned-registry", "repository:sample:pull"
				switch attack {
				case "realm":
					endpoint += "/escape"
				case "service":
					service = "foreign-service"
				case "scope":
					scope = "repository:sample:pull,push"
				}
				challenge := fmt.Sprintf(`Bearer realm=%q,service=%q,scope=%q`, endpoint, service, scope)
				if attack == "duplicate" {
					challenge += `,realm="https://foreign.example/token"`
				}
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(401)
			}))
			defer origin.Close()
			server := New(nil, nil, "")
			server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			server.UpstreamCredentials["test-a/realm"] = UpstreamCredential{Value: "owned-user:owned-realm-password", AllowedURL: realm.URL + "/token", Authentication: "basic"}
			repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, OCITokenEndpoint: &upstream.Config{URL: realm.URL + "/token", Networks: []string{"127.0.0.1/32"}, CredentialRef: "realm", Authentication: "basic"}, OCITokenService: "owned-registry"}}
			client, e := server.newOCIRegistryClient(store.Identity{Tenant: "test-a"}, repo, "sample")
			if e != nil {
				t.Fatal(e)
			}
			defer client.close()
			response, e := client.get(context.Background(), "sample/manifests/latest", nil, nil)
			if attack == "valid" {
				if e != nil {
					t.Fatal(e)
				}
				defer response.Body.Close()
				body, _ := io.ReadAll(response.Body)
				if response.StatusCode != 200 || string(body) != "exact registry response" || exchanges.Load() != 1 || requests.Load() != 2 {
					t.Fatalf("challenge exchange: %s %v %d %d", body, e, exchanges.Load(), requests.Load())
				}
			} else if attack == "token-redirect" {
				if !errors.Is(e, upstream.ErrRedirect) || exchanges.Load() != 1 {
					t.Fatalf("token redirect was followed: %v exchanges %d", e, exchanges.Load())
				}
			} else if !errors.Is(e, upstream.ErrDestination) || exchanges.Load() != 0 {
				t.Fatalf("authority attack accepted: %v exchanges %d", e, exchanges.Load())
			}
		})
	}
}

func TestOCIProxyRejectsIncompleteOrMismatchedGraph(t *testing.T) {
	for _, bad := range []string{"digest", "size", "media", "missing", "budget"} {
		t.Run(bad, func(t *testing.T) {
			config := []byte("{}")
			digest := "sha256:" + crypt.Digest(config)
			descriptor := map[string]any{"digest": digest, "size": len(config), "mediaType": "application/vnd.example.config"}
			if bad == "digest" {
				descriptor["digest"] = "sha256:" + strings.Repeat("a", 64)
			}
			if bad == "size" {
				descriptor["size"] = 3
			}
			document := map[string]any{"schemaVersion": 2, "mediaType": testOCIImage, "config": descriptor, "layers": []any{}}
			data, _ := json.Marshal(document)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/manifests/") {
					w.Header().Set("Content-Type", testOCIImage)
					if bad == "media" {
						w.Header().Set("Content-Type", testOCIIndex)
					}
					w.Write(data)
					return
				}
				if bad == "missing" {
					w.WriteHeader(404)
					return
				}
				w.Write(config)
			}))
			defer origin.Close()
			objects, e := blob.New(t.TempDir(), 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			server := New(nil, objects, "")
			server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			if bad == "budget" {
				server.OCIGraphBytes = 1
			}
			repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}}}
			i := store.Identity{Tenant: "test-a"}
			client, e := server.newOCIRegistryClient(i, repo, "sample")
			if e != nil {
				t.Fatal(e)
			}
			defer client.close()
			fill := ociGraphFill{server: server, client: client, ctx: context.Background(), identity: i, repo: repo, image: "sample", objects: map[string]store.Artifact{}, stack: map[string]bool{}}
			if _, e = fill.manifest("latest", nil, nil, 0); e == nil {
				t.Fatal("unverified graph accepted")
			}
		})
	}
}

func FuzzOCIChallenge(f *testing.F) {
	f.Add(`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:sample:pull"`)
	f.Add(`Bearer realm="unterminated`)
	f.Fuzz(func(t *testing.T, raw string) {
		m, e := parseOCIChallenge(raw)
		if e == nil && (m["realm"] == "" || m["service"] == "") {
			t.Fatal("unbound challenge")
		}
	})
}
