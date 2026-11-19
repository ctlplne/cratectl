//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func cranBinaryFixture(t *testing.T, built, payload string, windows bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	files := [][2]string{
		{"DESCRIPTION", "Package: CratectlBinary\nVersion: 1.2-3\nLicense: MIT\nNeedsCompilation: no\nBuilt: " + built + "\n"},
		{"Meta/package.rds", "opaque inspection fixture\n"},
		{"extdata/owned.txt", payload},
	}
	const directory = "CratectlBinary/"
	if windows {
		archive := zip.NewWriter(&buffer)
		for _, file := range files {
			writer, err := archive.Create(directory + file[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(writer, file[1]); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	for _, file := range files {
		if err := archive.WriteHeader(&tar.Header{Name: directory + file[0], Size: int64(len(file[1])), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, file[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestCRANHostedBinaryChannelsBindOriginalArchiveAndCurrentPolicy(t *testing.T) {
	s, _, owner, admin := schemaServer(t)
	ctx := context.Background()
	const repo = "cratectl-cran-binary"
	const route = "/cran/" + repo + "/"
	const mac = "bin/macosx/sonoma-arm64/contrib/4.6/"
	const otherMac = "bin/macosx/big-sur-x86_64/contrib/4.6/"
	const otherSeries = "bin/macosx/sonoma-arm64/contrib/4.5/"
	const windows = "bin/windows/contrib/4.6/"
	const app = "CratectlBinary_1.2-3"
	const sourcePath = "src/contrib/" + app + ".tar.gz"
	const macBuilt = "R 4.6.2; aarch64-apple-darwin23; 2026-11-19; unix"
	const winBuilt = "R 4.6.2; ; 2026-11-19; windows"
	macBytes := cranBinaryFixture(t, macBuilt, "exact macOS archive", false)
	winBytes := cranBinaryFixture(t, winBuilt, "exact Windows archive", true)
	source := cranSourceFixture(t, "CratectlBinary", "1.2-3", "Description: owned source\n", "same coordinate source")
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "cran", RequireReview: true})

	call := func(method, path string, body []byte, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, s, owner, method, route+path, body, "", headers...)
		if w.Code != status {
			t.Fatalf("CRAN %s %s returned %d, expected %d: %.250s", method, path, w.Code, status, w.Body.String())
		}
		return w
	}
	decide := func(path string, archive []byte, decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, path, crypt.Digest(archive), decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	call("PUT", mac+app+".tgz", source, 400)
	call("PUT", otherMac+app+".tgz", macBytes, 400)
	call("PUT", otherSeries+app+".tgz", macBytes, 400)
	call("PUT", windows+app+".zip", macBytes, 400)
	call("PUT", windows+app+".tgz", macBytes, 404)
	for _, item := range []struct {
		path, directory, mustContain, media string
		data                                []byte
	}{
		{sourcePath, "src/contrib/", "Description: owned source", "application/gzip", source},
		{mac + app + ".tgz", mac, "Built: " + macBuilt, "application/gzip", macBytes},
		{windows + app + ".zip", windows, "Built: " + winBuilt, "application/zip", winBytes},
	} {
		if w := call("PUT", item.path, item.data, 201); w.Header().Get("X-Checksum-Sha256") != crypt.Digest(item.data) {
			t.Fatal("publication did not report the original SHA-256", item.path)
		}
		call("GET", item.path, nil, 403)
		if w := call("GET", item.directory+"PACKAGES", nil, 200); w.Body.Len() != 0 {
			t.Fatal("unreviewed bytes entered a package index", item.directory)
		}
		decide(item.path, item.data, "allowed")
		w := call("GET", item.directory+"PACKAGES", nil, 200)
		if strings.Count(w.Body.String(), "Package: CratectlBinary\n") != 1 || !strings.Contains(w.Body.String(), item.mustContain) {
			t.Fatal("index mixed independent archives or lost the binary build binding", item.directory, w.Body.String())
		}
		call("GET", item.directory+"PACKAGES", nil, 304, "If-None-Match", w.Header().Get("ETag"))
		w = call("GET", item.path, nil, 206, "Range", "bytes=1-5")
		if !bytes.Equal(w.Body.Bytes(), item.data[1:6]) || w.Header().Get("Content-Type") != item.media {
			t.Fatal("native range or archive media changed", item.path)
		}
	}
	call("GET", mac+"PACKAGES.rds", nil, 404)
	call("PUT", mac+app+".tgz", cranBinaryFixture(t, macBuilt, "different original bytes", false), 409)
	decide(mac+app+".tgz", macBytes, "denied")
	call("GET", mac+app+".tgz", nil, 403)
	if w := call("GET", mac+"PACKAGES", nil, 200); w.Body.Len() != 0 {
		t.Fatal("denied binary still appeared in its index")
	}
	if w := call("GET", windows+app+".zip", nil, 200); !bytes.Equal(w.Body.Bytes(), winBytes) {
		t.Fatal("denial changed bytes on a separate platform channel")
	}
}
