//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func debianPackageFixture(t *testing.T, control, payload string) []byte {
	t.Helper()
	makeTar := func(name, data string) []byte {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		archive := tar.NewWriter(gz)
		if err := archive.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, data); err != nil {
			t.Fatal(err)
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	for _, part := range []struct {
		name string
		body []byte
	}{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", makeTar("./control", control)},
		{"data.tar.gz", makeTar("./usr/share/cratectl/owned.txt", payload)}} {
		fmt.Fprintf(&archive, "%-16s%-12d%-6d%-6d%-8d%-10d`\n", part.name, 0, 0, 0, 644, len(part.body))
		archive.Write(part.body)
		if len(part.body)%2 != 0 {
			archive.WriteByte('\n')
		}
	}
	return archive.Bytes()
}

func TestDebianHostedBindsExactPackagesAndCurrentTenantPolicy(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	const repository = "cratectl-debian"
	const route = "/apt/" + repository + "/"
	const field = "pool/cratectl-apt/1:1.0-2/amd64/cratectl-apt.deb"
	const control = "Package: cratectl-apt\nVersion: 1:1.0-2\nArchitecture: amd64\nMaintainer: cratectl owned fixture\n" +
		"Depends: cratectl-apt-dependency (>= 1.0)\nDescription: Owned Debian archive\n Exact inert content.\n"
	mavenRepositories(t, s, admin, store.Repository{Name: repository, Format: "apt", Access: "restricted", RequireReview: true})
	data := debianPackageFixture(t, control, "Owned tenant A Debian fixture.\n")
	otherData := debianPackageFixture(t, control, "Owned tenant B Debian fixture.\n")
	call := func(server *Server, credential, method, path string, body []byte, expected int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, server, credential, method, route+path, body, "", headers...)
		if w.Code != expected {
			t.Fatalf("Debian %s %s returned %d, want %d: %.350s", method, path, w.Code, expected, w.Body.String())
		}
		return w
	}
	call(s, token, "PUT", field, data, 201)
	call(s, token, "PUT", strings.Replace(field, "amd64", "arm64", 1), data, 409)
	call(s, token, "PUT", field, otherData, 409)
	call(s, token, "GET", field, nil, 403)
	w := call(s, token, "GET", "Packages", nil, 200)
	if w.Body.Len() != 0 {
		t.Fatal("unreviewed Debian package leaked into the index")
	}
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-apt-reader"
	if err := store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	call(s, reader, "GET", "Packages", nil, 403)
	api := lifecycleHTTP(t, s, token)
	if w = api("PUT", "/api/v1/repositories/"+repository+"/grants", map[string]any{"actor": actor, "read": true}, "cratectl-apt-grant"); w.Code != 200 {
		t.Fatal("grant Debian repository reader", w.Code)
	}
	decide := func(decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repository, field, crypt.Digest(data), decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide("allowed")
	expected := control + "Filename: " + field + "\nSize: " + strconv.Itoa(len(data)) + "\nSHA256: " + crypt.Digest(data) + "\n\n"
	w = call(s, reader, "GET", "Packages", nil, 200)
	if w.Body.String() != expected {
		t.Fatal("Debian index did not bind the exact accepted control and archive", w.Body.String())
	}
	etag := w.Header().Get("ETag")
	call(s, reader, "GET", "Packages", nil, 304, "If-None-Match", etag)
	w = call(s, reader, "GET", "Packages.gz", nil, 200)
	gzipBody, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	unzipped, err := io.ReadAll(io.LimitReader(gzipBody, 4096))
	if err != nil || gzipBody.Close() != nil || string(unzipped) != expected {
		t.Fatal("gzip and plain Debian indexes disagree", err)
	}
	w = call(s, reader, "GET", field, nil, 206, "Range", "bytes=1-7")
	if !bytes.Equal(w.Body.Bytes(), data[1:8]) {
		t.Fatal("partial Debian archive did not preserve exact bytes")
	}
	decide("denied")
	w = call(s, reader, "GET", "Packages", nil, 200, "If-None-Match", etag)
	if w.Body.Len() != 0 {
		t.Fatal("currently denied Debian package remained indexed")
	}
	call(s, reader, "GET", field, nil, 403)
	decide("allowed")
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	w = call(restarted, reader, "GET", field, nil, 200)
	if !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("exact Debian package failed after handler restart")
	}
	otherToken, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(ctx, database.OwnerDSN, "cratectl-apt-other", "cratectl-apt-admin", "admin", otherToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other, err := s.DB.Authenticate(ctx, otherToken)
	if err != nil {
		t.Fatal(err)
	}
	call(s, otherToken, "GET", field, nil, 404)
	mavenRepositories(t, s, other, store.Repository{Name: repository, Format: "apt"})
	call(s, otherToken, "PUT", field, otherData, 201)
	w = call(s, otherToken, "GET", field, nil, 200)
	if !bytes.Equal(w.Body.Bytes(), otherData) {
		t.Fatal("other Debian tenant received conflicting primary tenant bytes")
	}
}
