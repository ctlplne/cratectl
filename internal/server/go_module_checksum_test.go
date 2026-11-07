// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

type publicGoChecksum struct {
	Module    string            `json:"module"`
	Version   string            `json:"version"`
	ZIPHash   string            `json:"zip_h1"`
	ModHash   string            `json:"mod_h1"`
	Key       string            `json:"verifier_key"`
	Initial   []byte            `json:"initial_checkpoint"`
	Advanced  []byte            `json:"advanced_checkpoint"`
	Responses map[string][]byte `json:"responses"`
}

func goChecksumPublic(t *testing.T) publicGoChecksum {
	t.Helper()
	raw, err := os.ReadFile("testdata/go-checksum-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var out publicGoChecksum
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func goChecksumServer(t *testing.T, url string, f publicGoChecksum) (*Server, store.Identity, store.Repository) {
	t.Helper()
	objects, err := blob.New(t.TempDir(), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil, objects, "")
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	i := store.Identity{Tenant: "checksum-team", Actor: "operator", Role: "admin"}
	r := store.Repository{Name: "source", Format: "go", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: url + "/go/source/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60}, GoChecksumAuthority: &store.GoChecksumAuthority{Endpoint: upstream.Config{URL: url + "/checksum/", Networks: []string{"127.0.0.1/32"}}, VerifierKey: f.Key, InitialCheckpoint: f.Initial, ProofPolicy: &store.GoChecksumProofPolicy{Mode: "retained"}}}}
	return s, i, r
}

func TestGoModuleChecksumFetchUsesConfiguredAuthorityAndStagesOriginalProof(t *testing.T) {
	for _, scenario := range []string{"public", "bearer", "basic", "advanced-pin", "no-store-opt-in"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := goChecksumPublic(t)
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if !strings.HasPrefix(r.URL.Path, "/checksum/") || r.Method != "GET" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("proof escaped configured authority/representation")
					w.WriteHeader(400)
					return
				}
				if scenario == "bearer" && r.Header.Get("Authorization") != "Bearer owned-checksum-standin" {
					t.Error("configured tenant credential missing")
					w.WriteHeader(401)
					return
				}
				if scenario == "basic" {
					u, p, ok := r.BasicAuth()
					if !ok || u != "owned" || p != "standin" {
						t.Error("configured basic credential missing")
						w.WriteHeader(401)
						return
					}
				}
				if scenario == "no-store-opt-in" {
					w.Header().Set("Cache-Control", "no-store")
				}
				body, ok := fixture.Responses[strings.TrimPrefix(r.URL.Path, "/checksum")]
				if !ok {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write(body)
			}))
			s, i, repo := goChecksumServer(t, origin.URL, fixture)
			if scenario == "bearer" || scenario == "basic" {
				authentication, value := "bearer", "owned-checksum-standin"
				if scenario == "basic" {
					authentication, value = "basic", "owned:standin"
				}
				repo.Settings.GoChecksumAuthority.Endpoint.CredentialRef = "checksum"
				repo.Settings.GoChecksumAuthority.Endpoint.Authentication = authentication
				s.UpstreamCredentials[i.Tenant+"/checksum"] = UpstreamCredential{Value: value, AllowedURL: origin.URL + "/checksum/", Authentication: authentication}
			}
			if scenario == "no-store-opt-in" {
				repo.Settings.Cache.AllowNoStore = true
			}
			c, representations := goOriginBytes(t)
			inspected, err := gomodule.InspectRepresentations(context.Background(), bytes.NewReader(representations["zip"]), int64(len(representations["zip"])), c, representations["mod"], representations["info"], ziparchive.Limits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64})
			if err != nil || inspected.ZIPHash != fixture.ZIPHash || inspected.GoModHash != fixture.ModHash {
				t.Fatal("public proof fixture does not bind actual inspected owned ZIP/mod", err)
			}
			pinned := fixture.Initial
			if scenario == "advanced-pin" {
				pinned = fixture.Advanced
			}
			fetched, err := s.fetchGoModuleChecksumProof(context.Background(), i, repo, c, inspected.ZIPHash, inspected.GoModHash, pinned)
			if err != nil || fetched.Object.Size == 0 || calls.Load() < 2 || calls.Load() > 4 || !bytes.Equal(fetched.Verified.Checkpoint, fixture.Advanced) {
				t.Fatal("configured checksum collection failed", err, calls.Load())
			}
			file, err := s.Blobs.OpenVerified(context.Background(), i.Tenant, fetched.Object.Digest, fetched.Object.Size)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(file)
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
			var proof store.GoModuleChecksumProof
			if err = json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(proof, fetched.Proof) || !bytes.Equal(proof.Snapshot.Checkpoint, pinned) || proof.Snapshot.VerifierKey != fixture.Key || fetched.Object.Digest != crypt.Digest(raw) {
				t.Fatal("staged proof changed original responses or trust binding")
			}
			for path, data := range proof.Snapshot.Responses {
				if !bytes.Equal(data, fixture.Responses[path]) {
					t.Fatal("original proof response changed")
				}
			}
			verified, err := store.VerifyGoModuleChecksumProof(context.Background(), proof, c, inspected.ZIPHash, inspected.GoModHash, fixture.Key, pinned)
			if err != nil || !reflect.DeepEqual(verified, fetched.Verified) {
				t.Fatal("staged proof cannot replay independently offline", err)
			}
		})
	}
}

func TestGoModuleChecksumFetchRejectsAuthorityNetworkCredentialAndResponseFaults(t *testing.T) {
	for _, scenario := range []string{"missing-authority", "missing-pin", "bad-key", "network", "private-network", "other-tenant", "credential-scope", "budget", "cancelled", "mid-cancel", "redirect", "status", "partial", "encoding", "range", "trailer", "duplicate-header", "no-store", "missing-tile", "forged-lookup", "declared-overflow", "chunked-overflow"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := goChecksumPublic(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls, outside atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if !strings.HasPrefix(r.URL.Path, "/checksum/") {
					outside.Add(1)
					w.WriteHeader(400)
					return
				}
				path := strings.TrimPrefix(r.URL.Path, "/checksum")
				body, ok := fixture.Responses[path]
				if scenario == "mid-cancel" {
					cancel()
				}
				switch scenario {
				case "redirect":
					w.Header().Set("Location", "/outside/credential-target")
					w.WriteHeader(302)
					return
				case "status":
					w.WriteHeader(304)
					return
				case "partial":
					w.WriteHeader(206)
					return
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "range":
					w.Header().Set("Content-Range", "bytes 0-1/3")
				case "trailer":
					w.Header().Set("Trailer", "X-Checksum-Trailer")
				case "duplicate-header":
					w.Header().Add("ETag", "one")
					w.Header().Add("ETag", "two")
				case "no-store":
					w.Header().Set("Cache-Control", "no-store")
				case "missing-tile":
					if strings.HasPrefix(path, "/tile/") {
						w.WriteHeader(404)
						return
					}
				case "forged-lookup":
					if strings.HasPrefix(path, "/lookup/") {
						body = bytes.Replace(body, []byte(fixture.ZIPHash), []byte(fixture.ModHash), 1)
					}
				case "declared-overflow":
					w.Header().Set("Content-Length", "65537")
					_, _ = w.Write(bytes.Repeat([]byte{'x'}, 65537))
					return
				case "chunked-overflow":
					w.(http.Flusher).Flush()
					_, _ = w.Write(bytes.Repeat([]byte{'x'}, 65537))
					return
				}
				if !ok {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write(body)
			}))
			s, i, repo := goChecksumServer(t, origin.URL, fixture)
			pinned := fixture.Initial
			zeroCalls := false
			switch scenario {
			case "missing-authority":
				repo.Settings.GoChecksumAuthority = nil
				zeroCalls = true
			case "missing-pin":
				pinned = nil
				zeroCalls = true
			case "bad-key":
				repo.Settings.GoChecksumAuthority.VerifierKey += "bad"
				zeroCalls = true
			case "network":
				repo.Settings.GoChecksumAuthority.Endpoint.Networks = []string{"192.0.2.0/24"}
				zeroCalls = true
			case "private-network":
				s.PrivateUpstreamNetworks = nil
				zeroCalls = true
			case "other-tenant", "credential-scope":
				repo.Settings.GoChecksumAuthority.Endpoint.CredentialRef = "checksum"
				s.UpstreamCredentials[i.Tenant+"/checksum"] = UpstreamCredential{Value: "owned-checksum-standin", AllowedURL: origin.URL + "/checksum/"}
				if scenario == "other-tenant" {
					i.Tenant = "different-team"
				} else {
					s.UpstreamCredentials[i.Tenant+"/checksum"] = UpstreamCredential{Value: "owned-checksum-standin", AllowedURL: origin.URL + "/wrong/"}
				}
				zeroCalls = true
			case "budget":
				s.NativeMetadataBytes = 192
				zeroCalls = true
			case "cancelled":
				cancel()
				zeroCalls = true
			}
			got, err := s.fetchGoModuleChecksumProof(ctx, i, repo, gomodule.Coordinate{Module: fixture.Module, Version: fixture.Version}, fixture.ZIPHash, fixture.ModHash, pinned)
			if err == nil || !reflect.DeepEqual(got, goChecksumFetch{}) || outside.Load() != 0 || zeroCalls && calls.Load() != 0 {
				t.Fatal("fault returned partial proof or escaped authority/preflight", err, calls.Load(), outside.Load())
			}
			if scenario == "cancelled" || scenario == "mid-cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			}
		})
	}
}

func TestGoModuleChecksumFetchDoesNotBypassDurableBundleAdmission(t *testing.T) {
	fixture := goChecksumPublic(t)
	var calls atomic.Int32
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	s, i, repo := goChecksumServer(t, origin.URL, fixture)
	c := gomodule.Coordinate{Module: fixture.Module, Version: fixture.Version}
	for _, required := range []bool{false, true} {
		repo.Settings.Cache.RequireChecksum = required
		result, err := s.fetchGoModuleBundle(context.Background(), i, repo, store.Retrieval{Repository: repo.Name, Path: c.Prefix() + ".zip", SourceRevision: repo.SourceRevision})
		if !errors.Is(err, errGoModuleChecksumPublicationRequired) || result.GoModule != nil || calls.Load() != 0 {
			t.Fatal("configured proof bypassed durable bundle checkpoint/publication admission", err, calls.Load())
		}
	}
}
