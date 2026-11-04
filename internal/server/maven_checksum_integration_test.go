//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestMavenChecksumAliasesShareParentPolicyGrantAndTenant(t *testing.T) {
	s, d, token, i := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, i,
		store.Repository{Name: "first", Format: "maven", RequireReview: true, Access: "restricted"},
		store.Repository{Name: "combined", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first"}}})
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, d.OwnerDSN, i.Tenant, "checksum-reader", "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	grant := func(allowed bool) {
		t.Helper()
		if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'first','checksum-reader',$2,false)ON CONFLICT(tenant,repository,actor)DO UPDATE SET can_read=excluded.can_read`, i.Tenant, allowed)
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide := func(p, digest, decision string) {
		t.Helper()
		if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
			_, e := store.Decide(ctx, tx, i, "first", p, digest, decision)
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	grant(true)
	p, body := "org/example/tool/1.0/tool-1.0.pom", "owned tenant-a publication"
	mavenPut(t, s, token, "first", p, body)
	aliases := map[string]string{"sha1": "sha1", "md5": "md5", "sha256": "sha256", "SHA-256": "sha256", "sha512": "sha512", "SHA-512": "sha512", "sha384": "sha384", "SHA-384": "sha384"}
	for suffix, algorithm := range aliases {
		h := crypt.CompatibilityHash(algorithm)
		_, _ = h.Write([]byte(body))
		sum := hex.EncodeToString(h.Sum(nil))
		if w := mavenHTTP(t, s, token, "PUT", "/r/first/"+p+"."+suffix, sum); w.Code != 201 {
			t.Fatal("publisher checksum rejected", suffix, w.Code)
		}
		if w := mavenHTTP(t, s, token, "PUT", "/r/first/"+p+"."+suffix, strings.Repeat("0", len(sum))); w.Code != 400 {
			t.Fatal("mismatched checksum accepted", suffix, w.Code)
		}
		if w := mavenHTTP(t, s, reader, "PUT", "/r/first/"+p+"."+suffix, sum); w.Code != 403 {
			t.Fatal("reader could publish checksum", suffix, w.Code)
		}
		if w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+p+"."+suffix, ""); w.Code != 403 {
			t.Fatal("checksum bypassed unassessed parent", suffix, w.Code)
		}
	}
	artifacts, err := s.DB.Artifacts(ctx, i, "first", "", true)
	if err != nil || len(artifacts) != 1 || artifacts[0].Path != p {
		t.Fatal("checksum publication created independent references", len(artifacts), err)
	}
	decide(p, crypt.Digest([]byte(body)), "allowed")
	etags := map[string]string{}
	for suffix, algorithm := range aliases {
		h := crypt.CompatibilityHash(algorithm)
		_, _ = h.Write([]byte(body))
		sum := hex.EncodeToString(h.Sum(nil))
		w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+p+"."+suffix, "")
		if w.Code != 200 || w.Body.String() != sum {
			t.Fatal("group checksum differs from exact parent", suffix, w.Code)
		}
		etags[suffix] = w.Header().Get("ETag")
		w = mavenHTTP(t, s, reader, "HEAD", "/r/combined/"+p+"."+suffix, "")
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("checksum HEAD differs", suffix, w.Code)
		}
	}
	// Seed an opaque sidecar as an older server could have stored it. Its own
	// allowed decision must never replace the current parent authorization.
	legacy := "legacy opaque checksum bytes"
	object, err := s.Blobs.Put(ctx, i.Tenant, strings.NewReader(legacy), "", int64(len(legacy)))
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := p + ".SHA-256"
	if err = s.DB.Publish(ctx, i, "first", []store.Artifact{{Path: legacyPath, Digest: object.Digest, Size: object.Size, MediaType: "text/plain"}}); err != nil {
		t.Fatal(err)
	}
	decide(legacyPath, object.Digest, "allowed")
	if w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+legacyPath, ""); w.Code != 200 || w.Body.String() != crypt.Digest([]byte(body)) {
		t.Fatal("legacy sidecar replaced derived parent checksum", w.Code)
	}
	decide(p, crypt.Digest([]byte(body)), "denied")
	for suffix := range aliases {
		if w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+p+"."+suffix, "", "If-None-Match", etags[suffix]); w.Code != 403 {
			t.Fatal("conditional checksum bypassed current parent denial", suffix, w.Code)
		}
	}
	decide(p, crypt.Digest([]byte(body)), "allowed")
	grant(false)
	for suffix := range aliases {
		if w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+p+"."+suffix, "", "If-None-Match", etags[suffix]); w.Code != 403 {
			t.Fatal("conditional checksum bypassed revoked grant", suffix, w.Code)
		}
	}
	other, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, d.OwnerDSN, "maven-checksum-tenant-b", "operator", "admin", other, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := s.DB.Authenticate(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	mavenRepositories(t, s, otherIdentity, store.Repository{Name: "first", Format: "maven"})
	otherBody := "owned tenant-b collision"
	mavenPut(t, s, other, "first", p, otherBody)
	if w := mavenHTTP(t, s, other, "GET", "/r/first/"+p+".SHA-256", ""); w.Code != 200 || w.Body.String() != crypt.Digest([]byte(otherBody)) {
		t.Fatal("checksum crossed tenant", w.Code)
	}
	grant(true)
	if w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+p+".SHA-256", ""); w.Code != 200 || w.Body.String() != crypt.Digest([]byte(body)) {
		t.Fatal("tenant-b publication changed tenant-a checksum", w.Code)
	}
}
