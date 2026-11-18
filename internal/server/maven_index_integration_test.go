//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
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
)

func TestMavenHostedIndexBindsCurrentJARAndPOMPolicyAcrossTenants(t *testing.T) {
	s, db, token, admin := schemaServer(t)
	const repo = "cratectl-maven-index"
	const endpoint = "/r/" + repo + "/"
	const coordinates = "dev/ctlplne/cratectl-library/"
	const actor = "cratectl-index-reader"
	config := store.Repository{Name: repo, Format: "maven", Access: "restricted", RequireReview: true}
	mavenRepositories(t, s, admin, config)
	provision := func(tenant, role string) (string, store.Identity) {
		t.Helper()
		value, err := crypt.Token()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Provision(t.Context(), db.OwnerDSN, tenant, actor, role, value, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		identity, err := s.DB.Authenticate(t.Context(), value)
		if err != nil {
			t.Fatal(err)
		}
		return value, identity
	}
	reader, _ := provision(admin.Tenant, "reader")
	other, second := provision("cratectl-maven-index-other", "admin")
	mavenRepositories(t, s, second, config)
	put := func(auth, file, data string) string {
		t.Helper()
		w := mavenHTTP(t, s, auth, http.MethodPut, endpoint+file, data, "Content-Type", "application/octet-stream")
		if w.Code != http.StatusCreated {
			t.Fatal("publish release reference", w.Code, w.Body.String())
		}
		return crypt.Digest([]byte(data))
	}
	decision := func(auth, file, digest, value, key string) {
		t.Helper()
		w := lifecycleHTTP(t, s, auth)(http.MethodPut, "/api/v1/repositories/"+repo+"/decisions", map[string]string{
			"path": file, "digest": digest, "decision": value,
		}, key)
		if w.Code != http.StatusOK {
			t.Fatal("review release reference", w.Code, w.Body.String())
		}
	}
	const first = coordinates + "1.0.0/cratectl-library-1.0.0"
	const secondRelease = coordinates + "2.0.0/cratectl-library-2.0.0"
	const snapshot = coordinates + "3.0.0-SNAPSHOT/cratectl-library-3.0.0-SNAPSHOT"
	firstJAR := put(token, first+".jar", "owned first tenant JAR bytes")
	firstPOM := put(token, first+".pom", "<project><artifactId>cratectl-library</artifactId></project>")
	secondJAR := put(token, secondRelease+".jar", "owned incomplete release")
	otherJAR := put(other, first+".jar", "owned matching coordinates in the second tenant")
	otherPOM := put(other, first+".pom", "<project><artifactId>cratectl-library</artifactId></project>")
	decision(other, first+".jar", otherJAR, "allowed", "other-jar")
	decision(other, first+".pom", otherPOM, "allowed", "other-pom")
	decision(token, first+".jar", firstJAR, "allowed", "first-jar")
	decision(token, secondRelease+".jar", secondJAR, "allowed", "second-jar")
	for _, ext := range []string{".jar", ".pom"} {
		file := snapshot + ext
		digest := put(token, file, "owned snapshot bytes "+ext)
		decision(token, file, digest, "allowed", "snapshot"+ext)
	}
	read := func(auth string, fragments ...string) []byte {
		t.Helper()
		w := mavenHTTP(t, s, auth, http.MethodGet, endpoint+mavenIndexChunk, "")
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/gzip" ||
			w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("X-Checksum-Sha256") != crypt.Digest(w.Body.Bytes()) {
			t.Fatal("index response", w.Code, w.Header())
		}
		gz, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(gz, 4096))
		if err != nil || gz.Close() != nil || len(data) >= 4096 || !bytes.Contains(data, []byte("NexusIndex")) || len(data) < 9 || data[0] != 1 {
			t.Fatal("index transport", err, len(data))
		}
		for _, fragment := range fragments {
			present := !strings.HasPrefix(fragment, "!")
			if bytes.Contains(data, []byte(strings.TrimPrefix(fragment, "!"))) != present {
				t.Fatal("index visibility", fragment)
			}
		}
		return data
	}
	if w := mavenHTTP(t, s, reader, http.MethodGet, endpoint+mavenIndexChunk, ""); w.Code != http.StatusForbidden {
		t.Fatal("ungranted index access", w.Code)
	}
	api := lifecycleHTTP(t, s, token)
	grant := func(read bool, key string) {
		t.Helper()
		if w := api(http.MethodPut, "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": read, "write": false}, key); w.Code != http.StatusOK {
			t.Fatal("set reader grant", w.Code, w.Body.String())
		}
	}
	grant(true, "grant-index-reader")
	read(reader, "!cratectl-library|1.0.0|NA", "!2.0.0", "!3.0.0-SNAPSHOT")
	read(other, "dev.ctlplne|cratectl-library|1.0.0|NA", otherJAR, "!"+firstJAR)
	decision(token, first+".pom", firstPOM, "allowed", "first-pom")
	read(reader, "dev.ctlplne|cratectl-library|1.0.0|NA", firstJAR, "!"+otherJAR, "!2.0.0", "!3.0.0-SNAPSHOT")
	archive := mavenHTTP(t, s, reader, http.MethodGet, endpoint+mavenIndexChunk, "")
	checksum := mavenHTTP(t, s, reader, http.MethodGet, endpoint+mavenIndexChunk+".sha256", "")
	properties := mavenHTTP(t, s, reader, http.MethodGet, endpoint+mavenIndexProperties, "")
	indexDigest := crypt.Digest(archive.Body.Bytes())
	if checksum.Code != http.StatusOK || checksum.Body.String() != indexDigest || properties.Code != http.StatusOK ||
		!strings.Contains(properties.Body.String(), "nexus.index.id="+repo+"\n") ||
		!strings.Contains(properties.Body.String(), "cratectl.index.sha256="+indexDigest+"\n") {
		t.Fatal("properties and checksum must bind the exact index archive", checksum.Code, properties.Code)
	}
	etag := archive.Header().Get("ETag")
	if w := mavenHTTP(t, s, reader, http.MethodHead, endpoint+mavenIndexChunk, "", "If-None-Match", etag); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatal("conditional index", w.Code)
	}
	decision(token, first+".pom", firstPOM, "denied", "deny-index-pom")
	read(reader, "!cratectl-library|1.0.0|NA", "!"+firstJAR)
	grant(false, "revoke-index-reader")
	if w := mavenHTTP(t, s, reader, http.MethodGet, endpoint+mavenIndexChunk, "", "If-None-Match", etag); w.Code != http.StatusForbidden {
		t.Fatal("conditional read with revoked grant", w.Code)
	}
	if w := mavenHTTP(t, s, token, http.MethodPut, endpoint+mavenIndexChunk, "private fixture cannot publish the generated resource"); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("reserved generated file", w.Code)
	}
}

func TestMavenProxyIndexRequiresBothCurrentSourceReceipts(t *testing.T) {
	s, _, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	const repo = "cratectl-maven-index-proxy"
	const artifact = "dev/ctlplne/cratectl-index/1.0.0/cratectl-index-1.0.0"
	const originBase = "/cratectl-maven-index-origin/"
	const jar = "owned immutable Maven payload"
	const pom = `<project><artifactId>cratectl-index</artifactId></project>`
	var requests atomic.Int64
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body string
		switch strings.TrimSuffix(r.URL.Path, ".sha256") {
		case originBase + artifact + ".jar":
			body = jar
		case originBase + artifact + ".pom":
			body = pom
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			body = crypt.Digest([]byte(body))
		}
		w.Header().Set("Cache-Control", "max-age=120")
		_, _ = io.WriteString(w, body)
	})}}
	origin.Start()
	defer origin.Close()
	mavenRepositories(t, s, i, store.Repository{Name: repo, Format: "maven", Mode: "proxy", Settings: store.RepositorySettings{
		Upstream: &upstream.Config{URL: origin.URL + originBase, Networks: []string{"127.0.0.1/32"}},
		Cache:    store.CacheSettings{FreshSeconds: 120, RequireChecksum: true},
	}})
	const endpoint = "/r/" + repo + "/"
	read := func(expected bool) {
		t.Helper()
		before := requests.Load()
		w := mavenHTTP(t, s, token, http.MethodGet, endpoint+mavenIndexChunk, "")
		if w.Code != http.StatusOK {
			t.Fatal("cached index response", w.Code, w.Body.String())
		}
		gz, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(gz, 4096))
		if err != nil || gz.Close() != nil || bytes.Contains(data, []byte("dev.ctlplne|cratectl-index|1.0.0|NA")) != expected || requests.Load() != before {
			t.Fatal("cached native index did not match the authorized origin-independent view", expected, err)
		}
	}
	pull := func(ext, expected string) {
		t.Helper()
		w := mavenHTTP(t, s, token, http.MethodGet, endpoint+artifact+ext, "")
		if w.Code != http.StatusOK || w.Body.String() != expected {
			t.Fatal("ordinary proxy pull", w.Code, w.Body.String())
		}
	}
	read(false)
	pull(".jar", jar)
	read(false)
	pull(".pom", pom)
	read(true)
	api := lifecycleHTTP(t, s, token)
	if w := api(http.MethodPut, "/api/v1/repositories/"+repo+"/cache", map[string]string{"path": artifact + ".pom"}, "expire-index-proxy-pom"); w.Code != http.StatusOK {
		t.Fatal("expire the POM receipt", w.Code, w.Body.String())
	}
	read(false)
	pull(".pom", pom)
	read(true)
	mavenDeny(t, s, i, repo, artifact+".jar")
	read(false)
}

func TestMavenGroupIndexRespectsExactFileOrderAndMemberGrants(t *testing.T) {
	s, db, token, identity := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	const preferred = "cratectl-index-preferred"
	const jarRepo = "cratectl-index-jar"
	const pomRepo = "cratectl-index-pom"
	const group = "cratectl-index-group"
	const actor = "cratectl-index-reader"
	const coordinate = "dev/ctlplne/cratectl-index/1.0.0/cratectl-index-1.0.0"
	const jar = "owned lower Maven JAR"
	const pom = `<project><artifactId>cratectl-index</artifactId></project>`
	var requests atomic.Int64
	listener, err := testnet.ListenOwned()
	if err != nil {
		t.Fatal(err)
	}
	origin := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})}}
	origin.Start()
	defer origin.Close()
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(t.Context(), db.OwnerDSN, identity.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	mavenRepositories(t, s, identity,
		store.Repository{Name: jarRepo, Format: "maven"}, store.Repository{Name: pomRepo, Format: "maven"},
		store.Repository{Name: preferred, Mode: "proxy", Access: "restricted", Format: "maven", Settings: store.RepositorySettings{
			Upstream: &upstream.Config{URL: origin.URL + "/cratectl-maven-index-absent/", Networks: []string{"127.0.0.1/32"}},
			Cache:    store.CacheSettings{FreshSeconds: 120, NegativeSeconds: 120, RequireChecksum: true},
		}},
		store.Repository{Name: group, Mode: "group", Format: "maven", Settings: store.RepositorySettings{Members: []string{preferred, jarRepo, pomRepo}}})
	if w := mavenHTTP(t, s, token, http.MethodPut, "/r/"+jarRepo+"/"+coordinate+".jar", jar); w.Code != http.StatusCreated {
		t.Fatal("publish lower JAR", w.Code, w.Body.String())
	}
	if w := mavenHTTP(t, s, token, http.MethodPut, "/r/"+pomRepo+"/"+coordinate+".pom", pom); w.Code != http.StatusCreated {
		t.Fatal("publish lower POM", w.Code, w.Body.String())
	}
	read := func(expected bool) {
		t.Helper()
		before := requests.Load()
		w := mavenHTTP(t, s, reader, http.MethodGet, "/r/"+group+"/"+mavenIndexChunk, "")
		if w.Code != http.StatusOK {
			t.Fatal("group index response", w.Code, w.Body.String())
		}
		gz, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(gz, 4096))
		if err != nil || gz.Close() != nil || bytes.Contains(data, []byte(crypt.Digest([]byte(jar)))) != expected || requests.Load() != before {
			t.Fatal("Maven group discovery failed to enforce current receipts and grants", expected, err)
		}
	}
	api := lifecycleHTTP(t, s, token)
	grant := func(allow bool, key string) {
		t.Helper()
		w := api(http.MethodPut, "/api/v1/repositories/"+preferred+"/grants", map[string]any{"actor": actor, "read": allow, "write": false}, key)
		if w.Code != http.StatusOK {
			t.Fatal("set preferred Maven group grant", w.Code, w.Body.String())
		}
	}
	read(false)
	grant(true, "allow-preferred-maven-index")
	read(false)
	if w := mavenHTTP(t, s, reader, http.MethodGet, "/r/"+group+"/"+coordinate+".jar", ""); w.Code != http.StatusOK || w.Body.String() != jar {
		t.Fatal("ordinary group JAR fallback", w.Code, w.Body.String())
	}
	read(false)
	if w := mavenHTTP(t, s, reader, http.MethodGet, "/r/"+group+"/"+coordinate+".pom", ""); w.Code != http.StatusOK || w.Body.String() != pom {
		t.Fatal("ordinary group POM fallback", w.Code, w.Body.String())
	}
	read(true)
	grant(false, "revoke-preferred-maven-index")
	read(false)
	grant(true, "restore-preferred-maven-index")
	read(true)
	if w := api(http.MethodPut, "/api/v1/repositories/"+preferred+"/cache", map[string]string{"path": coordinate + ".pom"}, "expire-preferred-pom-receipt"); w.Code != http.StatusOK {
		t.Fatal("expire preferred POM absence", w.Code, w.Body.String())
	}
	read(false)
}
