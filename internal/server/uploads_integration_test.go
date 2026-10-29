//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func uploadFixture(t *testing.T) (*Server, context.Context, store.Identity, store.Repository) {
	t.Helper()
	if os.Getenv("CRATECTL_DSN") == "" {
		t.Fatal("CRATECTL_DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Pool.Close)
	i := store.Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	repo := store.Repository{Name: fmt.Sprintf("upload-%d", time.Now().UnixNano()), Format: "oci"}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return store.CreateRepository(ctx, tx, i, repo) }); e != nil {
		t.Fatal(e)
	}
	repo, e = db.Repository(ctx, i, repo.Name)
	if e != nil {
		t.Fatal(e)
	}
	b, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	return New(db, b, ""), ctx, i, repo
}
func beginUpload(t *testing.T, s *Server, ctx context.Context, i store.Identity, repo store.Repository) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	s.oci(w, r, i, repo, "app/blobs/uploads/")
	if w.Code != 202 {
		t.Fatalf("begin upload: %d %s", w.Code, w.Body.String())
	}
	return w.Header().Get("Docker-Upload-UUID")
}

func TestSlowOCIUploadDoesNotHoldTenantMutationLock(t *testing.T) {
	s, ctx, i, repo := uploadFixture(t)
	id := beginUpload(t, s, ctx, i, repo)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	bodyStarted := make(chan struct{})
	done := make(chan struct{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PATCH", "/", reader).WithContext(ctx)
	go func() { close(bodyStarted); s.oci(w, r, i, repo, "app/blobs/uploads/"+id); close(done) }()
	<-bodyStarted
	// The pipe write completes only when the server is reading the body.
	if _, e := writer.Write([]byte("first")); e != nil {
		t.Fatal(e)
	}
	progress := make(chan error, 1)
	go func() {
		progress <- s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, `SELECT 1`); return e })
	}()
	select {
	case e := <-progress:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(500 * time.Millisecond):
		writer.Close()
		<-done
		t.Fatal("slow upload body held tenant mutation lock")
	}
	writer.Close()
	<-done
	if w.Code != 202 {
		t.Fatalf("chunk: %d %s", w.Code, w.Body.String())
	}
	check := httptest.NewRecorder()
	s.oci(check, httptest.NewRequest("GET", "/", strings.NewReader("")).WithContext(ctx), i, repo, "app/blobs/uploads/"+id)
	if check.Code != 204 || check.Header().Get("Range") != "0-4" {
		t.Fatalf("ack offset: %d %v", check.Code, check.Header())
	}
}

func TestUploadHeartbeatCancellationAndCredentialExpiry(t *testing.T) {
	for _, test := range []string{"heartbeat", "cancel", "credential_expiry", "grant_revoked"} {
		t.Run(test, func(t *testing.T) {
			s, ctx, i, repo := uploadFixture(t)
			admin := i
			if e := s.ConfigureUploads(32, 4, 512, time.Second, 2*time.Second); e != nil {
				t.Fatal(e)
			}
			if test == "credential_expiry" || test == "grant_revoked" {
				expires := time.Now().Add(time.Hour)
				if test == "credential_expiry" {
					expires = time.Now().Add(1500 * time.Millisecond)
				}
				token, e := crypt.Token()
				if e != nil {
					t.Fatal(e)
				}
				if e = store.Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), i.Tenant, "upload-writer", "writer", token, expires); e != nil {
					t.Fatal(e)
				}
				i, e = s.DB.Authenticate(ctx, token)
				if e != nil {
					t.Fatal(e)
				}
			}
			if test == "grant_revoked" {
				if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
					if _, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET access='restricted' WHERE name=$1`, repo.Name); e != nil {
						return e
					}
					_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,$2,$3,true,true)`, i.Tenant, repo.Name, i.Actor)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}

			id := beginUpload(t, s, ctx, i, repo)
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				s.oci(w, httptest.NewRequest("PATCH", "/", reader).WithContext(ctx), i, repo, "app/blobs/uploads/"+id)
				close(done)
			}()
			if _, e := writer.Write([]byte("live bytes")); e != nil {
				t.Fatal(e)
			}
			switch test {
			case "heartbeat":
				time.Sleep(3 * time.Second)
				current, e := s.DB.Upload(ctx, i, repo.Name, "app", id)
				if e != nil || current.Offset != 0 {
					t.Fatal("live session expired or unacked bytes visible", current, e)
				}
				writer.Close()
				<-done
				if w.Code != 202 {
					t.Fatalf("renewed upload: %d %s", w.Code, w.Body.String())
				}
			case "cancel":
				cancel := httptest.NewRecorder()
				s.oci(cancel, httptest.NewRequest("DELETE", "/", nil).WithContext(ctx), i, repo, "app/blobs/uploads/"+id)
				if cancel.Code != 204 {
					t.Fatalf("cancel: %d %s", cancel.Code, cancel.Body.String())
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("cancel did not stop chunk I/O")
				}
				if w.Code != 409 {
					t.Fatalf("cancelled chunk accepted: %d %s", w.Code, w.Body.String())
				}
			case "grant_revoked":
				if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.repository_grants SET can_write=false WHERE repository=$1 AND actor=$2`, repo.Name, i.Actor)
					return e
				}); e != nil {
					t.Fatal(e)
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("revoked grant did not stop chunk I/O")
				}
				if w.Code != 403 {
					t.Fatalf("revoked grant accepted: %d %s", w.Code, w.Body.String())
				}

			case "credential_expiry":
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Fatal("expired credential did not stop chunk I/O")
				}
				if w.Code != 401 {
					t.Fatalf("expired credential accepted: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestLegacyUploadMigratesOnlyAcknowledgedPrefix(t *testing.T) {
	s, ctx, i, repo := uploadFixture(t)
	id := beginUpload(t, s, ctx, i, repo)
	if _, e := s.Blobs.AppendUpload(ctx, i.Tenant, id, 0, strings.NewReader("first-UNACKNOWLEDGED")); e != nil {
		t.Fatal(e)
	}
	if e := s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET parts_version=0,offset_bytes=5 WHERE id=$1`, id)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	digest := crypt.Digest([]byte("first-second"))
	w := httptest.NewRecorder()
	s.oci(w, httptest.NewRequest("PUT", "/?digest=sha256:"+digest, strings.NewReader("-second")).WithContext(ctx), i, repo, "app/blobs/uploads/"+id)
	if w.Code != 201 {
		t.Fatalf("legacy finalization: %d %s", w.Code, w.Body.String())
	}
	f, e := s.Blobs.OpenVerified(ctx, i.Tenant, digest, 12)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	data, e := io.ReadAll(f)
	if e != nil || string(data) != "first-second" {
		t.Fatal("legacy prefix mismatch", string(data), e)
	}
	if _, e = s.DB.Upload(ctx, i, repo.Name, "app", id); e != store.ErrNotFound {
		t.Fatal("completed session still active", e)
	}
}
