//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
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
