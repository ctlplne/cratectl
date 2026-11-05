//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleServingRechecksEarlierSourcesBeforeHeaders(t *testing.T) {
	for _, scenario := range []string{"new-allowed", "new-denied", "new-partial"} {
		t.Run(scenario, func(t *testing.T) {
			s, database, token, i := schemaServer(t)
			ctx := context.Background()
			mavenRepositories(t, s, i, store.Repository{Name: "higher", Format: "go", Access: "restricted"}, store.Repository{Name: "lower", Format: "go", Access: "restricted"}, store.Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", Settings: store.RepositorySettings{Members: []string{"higher", "lower"}}})
			c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/selection", Version: "v1.0.0"}
			lower, _ := goPublicationFixture(t, c, "lower source original bytes")
			if w := goHTTP(t, s, token, "PUT", "/go/lower/"+c.Prefix()+".zip", lower); w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			group, e := s.DB.Repository(ctx, i, "combined")
			if e != nil {
				t.Fatal(e)
			}
			resolved, e := s.resolve(ctx, i, group, c.Prefix()+".zip", false)
			if e != nil || resolved.source.Name != "lower" {
				t.Fatal("resolve original lower source", e)
			}
			f, e := s.Blobs.OpenVerified(ctx, i.Tenant, resolved.artifact.Digest, resolved.artifact.Size)
			if e != nil {
				t.Fatal(e)
			}
			f.Close()
			higher, _ := goPublicationFixture(t, c, "higher source distinct publication")
			if w := goHTTP(t, s, token, "PUT", "/go/higher/"+c.Prefix()+".zip", higher); w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			want, wantStatus := store.ErrConflict, 409
			query := ""
			if scenario == "new-denied" {
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='higher' AND right(path,4)='.zip'`
				want, wantStatus = store.ErrDenied, 403
			}
			if scenario == "new-partial" {
				query = `DELETE FROM cratectl.artifacts WHERE repository='higher' AND right(path,5)='.info'`
				want = store.ErrGoModuleUnvalidated
			}
			if query != "" {
				if strings.HasPrefix(query, "DELETE FROM ") {
					database.ExecDeleteFault(t, i.Tenant, query)
				} else if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = s.guardResolved(ctx, i, resolved); !errors.Is(e, want) {
				t.Fatal("higher source was bypassed after disk verification", scenario, e)
			}
			w := httptest.NewRecorder()
			s.serveResolvedArtifact(w, httptest.NewRequest("GET", "/go/combined/"+c.Prefix()+".zip", nil), i, resolved)
			if w.Code != wantStatus || w.Header().Get("X-Checksum-Sha256") != "" || w.Header().Get("ETag") != "" || bytes.HasPrefix(w.Body.Bytes(), []byte("PK")) {
				t.Fatal("old lower bytes/headers escaped final current selection", scenario, w.Code, w.Header())
			}
		})
	}
}
