//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func cranSourceFixture(t *testing.T, name, version, description, payload string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	for _, file := range []struct{ path, contents string }{
		{"DESCRIPTION", "Package: " + name + "\nVersion: " + version + "\nTitle: Owned CRAN Fixture\nLicense: MIT\n" + description},
		{"NAMESPACE", "# Owned inert CRAN fixture.\n"},
		{"inst/extdata/owned.txt", payload},
	} {
		if err := archive.WriteHeader(&tar.Header{Name: name + "/" + file.path, Size: int64(len(file.contents)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, file.contents); err != nil {
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

func TestCRANHostedSourceIndexAndRetainedBytes(t *testing.T) {
	s, database, owner, admin := schemaServer(t)
	ctx := context.Background()
	const repo = "cratectl-cran"
	const route = "/cran/" + repo + "/"
	const index = "src/contrib/PACKAGES"
	const app = "src/contrib/CratectlStats_1.2-3.tar.gz"
	const old = "src/contrib/CratectlStats_1.1.0.tar.gz"
	const dep = "src/contrib/Cratectl.Data_2.2-0.tar.gz"
	const metadata = "Description: Owned data profile with a\n  continued description.\nImports: Cratectl.Data (>= 2.1-0)\n" +
		"Remotes: ignored invalid.example/owned\nMD5sum: ignored-supplied-value\nNeedsCompilation: no\n"
	data := cranSourceFixture(t, "CratectlStats", "1.2-3", metadata, "Owned primary tenant archive.\n")
	duplicate := cranSourceFixture(t, "CratectlStats", "1.2-3", metadata, "Owned different tenant archive.\n")
	older := cranSourceFixture(t, "CratectlStats", "1.1.0", metadata, "Owned earlier version.\n")
	dependency := cranSourceFixture(t, "Cratectl.Data", "2.2-0", "Description: An owned dependency.\n", "Owned dependency bytes.\n")
	digest := crypt.Digest(data)
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "cran", Access: "restricted", RequireReview: true})
	call := func(server *Server, credential, method, nativePath string, body []byte, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, server, credential, method, route+nativePath, body, "", headers...)
		if w.Code != status {
			t.Fatalf("CRAN %s %s returned %d, expected %d: %.250s", method, nativePath, w.Code, status, w.Body.String())
		}
		return w
	}
	call(s, owner, "GET", index+".rds", nil, 404)
	call(s, owner, "PUT", old, data, 400)
	call(s, owner, "PUT", strings.Replace(app, "CratectlStats", "cratectlStats", 1), data, 400)
	if w := call(s, owner, "PUT", app, data, 201); w.Header().Get("X-Checksum-Sha256") != digest {
		t.Fatal("CRAN publish did not report the original archive digest")
	}
	call(s, owner, "PUT", old, older, 201)
	call(s, owner, "PUT", dep, dependency, 201)
	call(s, owner, "PUT", app, duplicate, 409)
	call(s, owner, "GET", app, nil, 403)
	if w := call(s, owner, "GET", index, nil, 200); w.Body.Len() != 0 {
		t.Fatal("unassessed CRAN archives were included in the index")
	}

	decide := func(path, digest, decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, path, digest, decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide(app, digest, "allowed")
	decide(old, crypt.Digest(older), "allowed")
	decide(dep, crypt.Digest(dependency), "allowed")
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-cran-reader"
	if err = store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	call(s, reader, "GET", index, nil, 403)
	api := lifecycleHTTP(t, s, owner)
	if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": true}, "cratectl-cran-grant"); w.Code != 200 {
		t.Fatalf("grant CRAN read: %d %.240s", w.Code, w.Body.String())
	}
	call(s, reader, "PUT", app, data, 403)
	w := call(s, reader, "GET", index, nil, 200)
	plain, etag := w.Body.String(), w.Header().Get("ETag")
	compatibility := crypt.CompatibilityHash("md5")
	compatibility.Write(data)
	if strings.Count(plain, "Package: ") != 3 || !strings.Contains(plain, "Version: 1.2-3\n") || !strings.Contains(plain, "Version: 1.1.0\n") ||
		!strings.Contains(plain, "Imports: Cratectl.Data (>= 2.1-0)\n") || !strings.Contains(plain, "MD5sum: "+hex.EncodeToString(compatibility.Sum(nil))+"\n") ||
		strings.Contains(plain, "ignored-supplied-value") || strings.Contains(plain, "invalid.example") {
		t.Fatal("CRAN metadata changed identity, review or native dependency fields", plain)
	}
	w = call(s, reader, "GET", index+".gz", nil, 200)
	z, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(io.LimitReader(z, 8192))
	if err != nil || z.Close() != nil || string(decoded) != plain {
		t.Fatal("plain and gzip CRAN index representations differ", err)
	}
	if _, err := s.DB.CRANPackageIndex(ctx, admin, repo, 2, 1<<20); !errors.Is(err, store.ErrMetadataLimit) {
		t.Fatal("CRAN index ignored its complete record budget", err)
	}
	call(s, reader, "GET", index, nil, 304, "If-None-Match", etag)
	if w := call(s, reader, "GET", app, nil, 206, "Range", "bytes=2-11"); !bytes.Equal(w.Body.Bytes(), data[2:12]) {
		t.Fatal("CRAN archive range altered original bytes")
	}
	decide(app, digest, "denied")
	w = call(s, reader, "GET", index, nil, 200, "If-None-Match", etag)
	if strings.Contains(w.Body.String(), "Version: 1.2-3\n") || !strings.Contains(w.Body.String(), "Version: 1.1.0\n") {
		t.Fatal("current CRAN policy removed the wrong version")
	}
	call(s, reader, "GET", app, nil, 403)
	decide(app, digest, "allowed")

	const lifecycle = "/api/v1/repositories/" + repo + "/artifacts/lifecycle"
	state, err := s.DB.ArtifactState(ctx, admin, repo, app)
	if err != nil {
		t.Fatal(err)
	}
	review := store.ArtifactStateRequest{Path: app, Digest: digest, Action: "delete", ExpectedRevision: state.Revision,
		Reason: "Retire the owned R source archive"}
	if w := api("PUT", lifecycle, review, "cratectl-cran-delete"); w.Code != 200 {
		t.Fatalf("delete CRAN archive: %d %.250s", w.Code, w.Body.String())
	}
	call(s, reader, "GET", app, nil, 404)
	if w := call(s, reader, "GET", index, nil, 200); strings.Contains(w.Body.String(), "Version: 1.2-3\n") {
		t.Fatal("retired CRAN package was still indexed")
	}
	state, err = s.DB.ArtifactState(ctx, admin, repo, app)
	if err != nil || !state.Deleted {
		t.Fatalf("inspect retired CRAN archive: %+v %v", state, err)
	}
	review.Action, review.ExpectedRevision = "restore", state.Revision
	review.Reason = "Restore the verified R source archive"
	if w := api("PUT", lifecycle, review, "cratectl-cran-restore"); w.Code != 200 {
		t.Fatalf("restore CRAN archive: %d %.250s", w.Code, w.Body.String())
	}
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	if w := call(restarted, reader, "GET", index, nil, 200); w.Body.String() != plain {
		t.Fatal("restored CRAN index did not reproduce the exact earlier view")
	}
	if w := call(restarted, reader, "GET", app, nil, 200); !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("restored CRAN source bytes changed after restart")
	}

	foreignToken, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, database.OwnerDSN, "cratectl-cran-other", "cratectl-cran-admin", "admin", foreignToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	foreign, err := s.DB.Authenticate(ctx, foreignToken)
	if err != nil {
		t.Fatal(err)
	}
	call(s, foreignToken, "GET", index, nil, 404)
	mavenRepositories(t, s, foreign, store.Repository{Name: repo, Format: "cran"})
	call(s, foreignToken, "PUT", app, duplicate, 201)
	if w := call(s, foreignToken, "GET", app, nil, 200); !bytes.Equal(w.Body.Bytes(), duplicate) {
		t.Fatal("other tenant received a conflicting CRAN archive")
	}
}
