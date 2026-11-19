//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/composer"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testnet"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestComposerProxyBindsStrongCatalogAndSeparateDownloadAuthority(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	s.PublicURL = "https://127.0.0.1:38443"
	networks := []string{"127.0.0.1/32"}
	s.PrivateUpstreamNetworks = networks
	ctx := context.Background()
	const repo = "cratectl-composer-proxy"
	const packages = "/cratectl-composer-packages/"
	const downloads = "/cratectl-composer-archives/"
	const root = "/composer/" + repo + "/"
	const index = "p2/cratectl/composer-app.json"
	coordinate := composer.Coordinate{Name: "cratectl/composer-app", Version: "1.2.3"}
	archive := composerFixture(t, "Owned original Composer origin ZIP.")
	replacement := composerFixture(t, "Owned different Composer origin ZIP.")
	digest := crypt.Digest(archive)
	locator := coordinate.Path() + "?sha256=" + digest
	path := store.ComposerProxyArchivePath(coordinate, digest)
	indexCredential, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	archiveCredential, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-composer-proxy-reader"
	if err := store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	authority := "http://" + listener.Addr().String()
	var mode atomic.Int32
	var metadataReads, archiveReads, foreignReads atomic.Int64
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=120")
		switch r.URL.Path {
		case packages + index:
			metadataReads.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+indexCredential {
				foreignReads.Add(1)
				w.WriteHeader(401)
				return
			}
			location := authority + downloads + "app.zip"
			if mode.Load() == 1 {
				location = authority + "/cratectl-composer-unapproved/app.zip"
			}
			requires := "^2.4"
			if mode.Load() == 2 {
				requires = "^9.9"
			}
			dist := map[string]string{"type": "zip", "url": location, "sha256": digest, "shasum": crypt.SHA1(archive)}
			if mode.Load() == 4 {
				delete(dist, "sha256")
			}
			if mode.Load() == 5 {
				w.Header().Set("Cache-Control", "no-cache")
			}
			version := map[string]any{"name": coordinate.Name, "version": coordinate.Version, "type": "library", "require": map[string]string{
				"cratectl/composer-lib": requires,
			}, "autoload": map[string]any{"psr-4": map[string]string{`Cratectl\`: "src/"}}, "dist": dist}
			_ = json.NewEncoder(w).Encode(map[string]any{"packages": map[string]any{coordinate.Name: []any{version}}})
		case downloads + "app.zip":
			archiveReads.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+archiveCredential {
				foreignReads.Add(1)
				w.WriteHeader(401)
				return
			}
			data := archive
			if mode.Load() == 3 {
				data = replacement
			}
			_, _ = w.Write(data)
		default:
			foreignReads.Add(1)
			w.WriteHeader(404)
		}
	})}}
	origin.Start()
	defer origin.Close()
	indexConfig := upstream.Config{URL: authority + packages, Networks: networks, CredentialRef: "cratectl-composer-index"}
	archiveConfig := upstream.Config{URL: authority + downloads, Networks: networks, CredentialRef: "cratectl-composer-archive"}
	s.UpstreamCredentials[admin.Tenant+"/"+indexConfig.CredentialRef] = UpstreamCredential{Value: indexCredential, AllowedURL: indexConfig.URL}
	s.UpstreamCredentials[admin.Tenant+"/"+archiveConfig.CredentialRef] = UpstreamCredential{Value: archiveCredential, AllowedURL: archiveConfig.URL}
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "composer", Mode: "proxy", Access: "restricted", RequireReview: true,
		Settings: store.RepositorySettings{Upstream: &indexConfig, DownloadSources: []upstream.Config{archiveConfig},
			Cache: store.CacheSettings{FreshSeconds: 120, NegativeSeconds: 30}}})
	request := func(server *Server, credential, target string, want int, force bool) *httptest.ResponseRecorder {
		t.Helper()
		var headers []string
		if force {
			headers = []string{"Cache-Control", "no-cache"}
		}
		w := nugetHTTP(t, server, credential, "GET", root+target, nil, "", headers...)
		if w.Code != want {
			t.Fatalf("Composer proxy %s returned %d, expected %d: %.300s", target, w.Code, want, w.Body.String())
		}
		return w
	}
	request(s, reader, index, 403, false)
	if metadataReads.Load()+archiveReads.Load() != 0 {
		t.Fatal("denied Composer reader contacted the upstream")
	}
	api := lifecycleHTTP(t, s, token)
	if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": true}, "cratectl-composer-proxy-grant"); w.Code != 200 {
		t.Fatal("grant Composer proxy reader", w.Code, w.Body.String())
	}
	request(s, reader, index, 404, false)
	request(s, reader, coordinate.Path(), 400, false)
	request(s, reader, coordinate.Path()+"?sha256="+crypt.Digest(replacement), 409, false)
	request(s, reader, locator, 403, false)
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
	w := request(s, reader, index, 200, false)
	if !strings.Contains(w.Body.String(), s.PublicURL+root+locator) || strings.Contains(w.Body.String(), authority+downloads) {
		t.Fatal("Composer metadata did not rebind the distribution to the local digest-pinned route")
	}
	if first := request(s, reader, locator, 200, false); !bytes.Equal(first.Body.Bytes(), archive) {
		t.Fatal("Composer proxy returned different bytes")
	}
	if warm := request(New(s.DB, s.Blobs, s.PublicURL), reader, locator, 200, false); !bytes.Equal(warm.Body.Bytes(), archive) ||
		metadataReads.Load() != 1 || archiveReads.Load() != 1 {
		t.Fatal("cached Composer archive did not survive restart without upstream traffic")
	}
	decide("denied")
	request(s, reader, index, 404, false)
	request(s, reader, locator, 403, false)
	decide("allowed")

	mode.Store(1)
	request(s, reader, index, 502, true)
	if archiveReads.Load() != 1 || foreignReads.Load() != 0 {
		t.Fatal("Composer metadata escaped the separate archive authority")
	}
	mode.Store(2)
	request(s, reader, index, 404, true)
	request(s, reader, locator, 409, false)
	mode.Store(5)
	request(s, reader, index, 200, true)
	request(s, reader, locator, 200, false)
	mode.Store(3)
	request(s, reader, locator, 502, true)
	state, err := s.DB.Retrieval(ctx, admin, repo, path)
	if err != nil || state.State != "failed" || state.LastError != "upstream_integrity_failure" {
		t.Fatal("Composer proxy did not retain the rejected checksum outcome", state.State, state.LastError, err)
	}
	if retained, err := s.DB.ArtifactForPublication(ctx, admin, repo, path); err != nil || retained.Digest != digest {
		t.Fatal("Composer proxy replaced the retained correct archive", err)
	}
	mode.Store(4)
	request(s, reader, index, 404, true)
	request(s, reader, locator, 404, false)
}
