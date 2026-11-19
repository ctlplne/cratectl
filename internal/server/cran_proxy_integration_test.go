//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/cran"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testnet"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestCRANProxyChecksCatalogArchiveAndReviewAgainstPostgreSQL(t *testing.T) {
	s, database, owner, admin := schemaServer(t)
	ctx := context.Background()
	networks := []string{"127.0.0.1/32"}
	s.PrivateUpstreamNetworks = networks
	const repo = "cratectl-cran-proxy"
	const route = "/cran/" + repo + "/"
	const base = "/cratectl-cran-origin/"
	const index = cran.SourceDirectory + "PACKAGES"
	const deps = "Imports: Cratectl.Data (>= 2.2-0)\n"
	coordinate := cran.Coordinate{Name: "CratectlStats", Version: "1.2-3"}
	archive := cranSourceFixture(t, coordinate.Name, coordinate.Version, deps, "owned origin source bytes\n")
	updated := cranSourceFixture(t, coordinate.Name, coordinate.Version, deps, "owned origin replacement bytes\n")
	digest := crypt.Digest(archive)
	path := cran.PinnedSourcePath(coordinate, digest)
	replacement := cran.PinnedSourcePath(coordinate, crypt.Digest(updated))
	credential, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-cran-proxy-reader"
	if err := store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	const (
		ordinary = iota
		wrongRequirements
		badArchiveBytes
		changedDigest
		missingSHA256
		noCache
		pauseArchive
	)
	var mode atomic.Int32
	var catalogs, packages, foreign atomic.Int64
	archiveStarted := make(chan struct{}, 1)
	resumeArchive := make(chan struct{})
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			foreign.Add(1)
			w.WriteHeader(401)
			return
		}
		current := mode.Load()
		w.Header().Set("Cache-Control", "max-age=180")
		if current == noCache {
			w.Header().Set("Cache-Control", "no-cache")
		}
		switch r.URL.Path {
		case base + index:
			catalogs.Add(1)
			data, imports := archive, deps
			if current == changedDigest {
				data = updated
			}
			if current == wrongRequirements {
				imports = "Imports: Cratectl.Data (>= 9.0)\n"
			}
			sum := crypt.CompatibilityHash("md5")
			_, _ = sum.Write(data)
			catalog := "Package: " + coordinate.Name + "\nVersion: " + coordinate.Version + "\nLicense: MIT\n" + imports +
				"MD5sum: " + hex.EncodeToString(sum.Sum(nil)) + "\n"
			if current != missingSHA256 {
				catalog += "SHA256sum: " + crypt.Digest(data) + "\n"
			}
			etag := `"` + crypt.Digest([]byte(catalog)) + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			_, _ = w.Write([]byte(catalog))
		case base + coordinate.Path():
			packages.Add(1)
			if current == pauseArchive {
				archiveStarted <- struct{}{}
				select {
				case <-resumeArchive:
				case <-r.Context().Done():
					return
				}
			}
			data := archive
			if current == changedDigest || current == badArchiveBytes {
				data = updated
			}
			_, _ = w.Write(data)
		default:
			foreign.Add(1)
			w.WriteHeader(404)
		}
	})}}
	origin.Start()
	defer origin.Close()
	defer func() {
		select {
		case <-resumeArchive:
		default:
			close(resumeArchive)
		}
	}()
	config := upstream.Config{URL: origin.URL + base, Networks: networks, CredentialRef: "cratectl-cran-origin"}
	s.UpstreamCredentials[admin.Tenant+"/"+config.CredentialRef] = UpstreamCredential{Value: credential, AllowedURL: config.URL}
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "cran", Mode: "proxy", Access: "restricted", RequireReview: true,
		Settings: store.RepositorySettings{Upstream: &config, Cache: store.CacheSettings{FreshSeconds: 180, NegativeSeconds: 20}}})
	get := func(serv *Server, target string, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, serv, reader, "GET", route+target, nil, "", headers...)
		if w.Code != status {
			t.Fatalf("CRAN proxy %s returned %d, expected %d: %.300s", target, w.Code, status, w.Body.String())
		}
		return w
	}
	get(s, index, 403)
	if catalogs.Load()+packages.Load() != 0 {
		t.Fatal("unauthorized request contacted the origin")
	}
	api := lifecycleHTTP(t, s, owner)
	if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": true}, "cratectl-cran-proxy-grant"); w.Code != 200 {
		t.Fatal("set grant", w.Code, w.Body.String())
	}
	get(s, coordinate.Path(), 404)
	get(s, replacement, 409)
	get(s, path, 403)
	if w := get(s, index, 200); w.Body.Len() != 0 {
		t.Fatal("unreviewed archive appeared in the index")
	}
	decide := func(decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, path, digest, decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide("allowed")
	if w := get(s, index, 200); !strings.Contains(w.Body.String(), "Path: sha256/"+digest) ||
		!strings.Contains(w.Body.String(), deps) || strings.Contains(w.Body.String(), origin.URL) {
		t.Fatal("CRAN index did not bind requirements to the native pinned URL", w.Body.String())
	}
	if w := get(New(s.DB, s.Blobs, s.PublicURL), path, 206, "Range", "bytes=4-9"); !bytes.Equal(w.Body.Bytes(), archive[4:10]) || catalogs.Load() != 1 || packages.Load() != 1 {
		t.Fatal("warm range did not preserve exact bytes without upstream traffic")
	}
	decide("denied")
	get(s, path, 403)
	if w := get(s, index, 200); w.Body.Len() != 0 || packages.Load() != 1 {
		t.Fatal("digest denial was not current at both native endpoints")
	}
	decide("allowed")
	mode.Store(wrongRequirements)
	if w := get(s, index, 200, "Cache-Control", "no-cache"); w.Body.Len() != 0 {
		t.Fatal("metadata disagreement advertised the cached archive")
	}
	get(s, path, 409)
	mode.Store(badArchiveBytes)
	get(s, path, 502, "Cache-Control", "no-cache")
	state, err := s.DB.Retrieval(ctx, admin, repo, path)
	if err != nil || state.State != "failed" || state.LastError != "upstream_integrity_failure" {
		t.Fatal("checksum mismatch did not retain the failure", state.State, state.LastError, err)
	}
	mode.Store(noCache)
	if w := get(s, path, 200, "Cache-Control", "no-cache"); !bytes.Equal(w.Body.Bytes(), archive) {
		t.Fatal("request-local admission lost a valid no-cache archive")
	}
	mode.Store(pauseArchive)
	pending := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		pending <- nugetHTTP(t, s, reader, "GET", route+path, nil, "", "Cache-Control", "no-cache")
	}()
	select {
	case <-archiveStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the owned archive request did not reach its pause")
	}
	mode.Store(changedDigest)
	get(s, index, 200, "Cache-Control", "no-cache")
	close(resumeArchive)
	select {
	case w := <-pending:
		if w.Code != 409 {
			t.Fatal("a refresh superseded the in-flight selection", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("superseded download did not stop")
	}
	get(s, path, 409)
	if retained, err := s.DB.ArtifactForPublication(ctx, admin, repo, path); err != nil || retained.Digest != digest {
		t.Fatal("changed metadata overwrote a retained digest-bound reference", err)
	}
	mode.Store(missingSHA256)
	get(s, index, 502, "Cache-Control", "no-cache")
	if foreign.Load() != 0 {
		t.Fatal("proxy used a wrong origin path or credential")
	}
}
