//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleLatestRechecksCurrentVersionAfterDiskVerification(t *testing.T) {
	for _, scenario := range []string{"unchanged", "new-release", "new-prerelease", "new-pseudo", "new-denied", "old-denied", "missing-sibling", "missing-all-before-resolution", "budget", "group-source-change", "group-reorder"} {
		t.Run(scenario, func(t *testing.T) {
			s, database, token, i := schemaServer(t)
			ctx := context.Background()
			mavenRepositories(t, s, i, store.Repository{Name: "higher", Format: "go", Access: "restricted"}, store.Repository{Name: "lower", Format: "go", Access: "restricted"}, store.Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", Settings: store.RepositorySettings{Members: []string{"higher", "lower"}}})
			c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/latest", Version: "v1.0.0"}
			instant := goFixtureInstant
			if scenario == "new-pseudo" {
				c.Version, instant = "v0.0.0-20260101030405-0123456789ab", "2026-01-01T03:04:05Z"
			}
			data, _ := goPublicationFixture(t, c, "original latest bytes")
			if w := goHTTP(t, s, token, "PUT", "/go/lower/"+c.Prefix()+".zip", data, "X-Cratectl-Module-Time", instant); w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			group, e := s.DB.Repository(ctx, i, "combined")
			if e != nil {
				t.Fatal(e)
			}
			a, e := s.resolve(ctx, i, group, c.Prefix()+".info", false)
			if e != nil {
				t.Fatal(e)
			}
			f, e := s.Blobs.OpenVerified(ctx, i.Tenant, a.artifact.Digest, a.artifact.Size)
			if e != nil {
				t.Fatal(e)
			}
			f.Close()
			a.goLatest = true
			want, status := error(nil), 200
			if strings.HasPrefix(scenario, "new-") {
				next := c
				next.Version = "v1.1.0"
				if scenario == "new-prerelease" {
					next.Version = "v1.1.0-beta"
				}
				if scenario == "new-pseudo" {
					next.Version = "v0.0.0-20260102030405-0123456789ab"
				}
				data, _ := goPublicationFixture(t, next, "new version after readback")
				if w := goHTTP(t, s, token, "PUT", "/go/higher/"+next.Prefix()+".zip", data); w.Code != 201 {
					t.Fatal(w.Code, w.Body.String())
				}
				if scenario == "new-release" || scenario == "new-pseudo" {
					want, status = store.ErrConflict, 409
				}
				if scenario == "new-denied" {
					if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='higher'`)
						return e
					}); e != nil {
						t.Fatal(e)
					}
				}
			}
			query := ""
			switch scenario {
			case "old-denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='lower'`
				want, status = store.ErrDenied, 403
			case "missing-sibling":
				database.ExecDeleteFault(t, i.Tenant, `DELETE FROM cratectl.artifacts WHERE repository='lower' AND right(path,4)='.zip'`)
				want, status = store.ErrGoModuleUnvalidated, 409
			case "missing-all-before-resolution":
				database.ExecDeleteFault(t, i.Tenant, `DELETE FROM cratectl.artifacts WHERE repository='lower'`)
				want, status = store.ErrConflict, 409
			case "budget":
				s.NativeMetadataBytes = 1
				want, status = store.ErrMetadataLimit, 503
			case "group-source-change":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='combined'`
				want, status = store.ErrSourceChanged, 503
			case "group-reorder":
				query = `UPDATE cratectl.repositories SET settings=jsonb_set(settings,'{members}','["lower","higher"]'),source_revision=source_revision+1 WHERE name='combined'`
				want, status = store.ErrSourceChanged, 503
			}
			if query != "" {
				if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query); return e }); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = s.guardResolved(ctx, i, a); !errors.Is(e, want) {
				t.Fatal("latest ignored current complete selection", scenario, e, want)
			}
			w := httptest.NewRecorder()
			s.serveResolvedArtifact(w, httptest.NewRequest("GET", "/go/combined/"+strings.Split(c.Prefix(), "/@v/")[0]+"/@latest", nil), i, a)
			if w.Code != status {
				t.Fatal("latest response did not enforce final guard", scenario, w.Code, status)
			}
			if want != nil && (w.Header().Get("X-Checksum-Sha256") != "" || w.Header().Get("ETag") != "" || bytes.Contains(w.Body.Bytes(), []byte(`"Version"`))) {
				t.Fatal("old latest bytes/headers escaped failed current selection")
			}
			if want == nil && !bytes.Contains(w.Body.Bytes(), []byte(c.Version)) {
				t.Fatal("allowed latest control lost original info bytes")
			}
			if scenario == "missing-all-before-resolution" {
				w = httptest.NewRecorder()
				s.serveGoModuleLatest(w, httptest.NewRequest("GET", "/go/combined/owned/@latest", nil), i, "combined", c.Prefix()+".info", nil)
				if w.Code != 409 || w.Header().Get("ETag") != "" {
					t.Fatal("known latest disappeared into client fallback", w.Code)
				}
			}
		})
	}
}

func TestGoModuleLatestBindsCurrentCatalogAndBundleAdmissions(t *testing.T) {
	for _, scenario := range []string{"fresh", "zero-catalog", "zero-bundle", "zero-both", "catalog-refresh-new", "catalog-expired", "bundle-expired", "catalog-denied", "bundle-denied", "wrong-catalog-generation", "wrong-bundle-generation"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			ctx := context.Background()
			c, files := goOriginBytes(t)
			catalogPath := store.GoModuleCatalogPath(c.Module)
			var newer atomic.Bool
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/go/source/"+strings.TrimPrefix(catalogPath, "go-catalog/")+"/@v/list" {
					if scenario == "zero-catalog" || scenario == "zero-both" || scenario == "wrong-catalog-generation" {
						w.Header().Set("Cache-Control", "no-cache")
					}
					if newer.Load() {
						w.Write([]byte("v1.0.0\nv1.1.0\n"))
					} else {
						w.Write([]byte("v1.0.0\n"))
					}
					return
				}
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				data, ok := files[kind]
				if !ok {
					t.Error("latest escaped fixed origin")
					w.WriteHeader(400)
					return
				}
				if scenario == "zero-bundle" || scenario == "zero-both" || scenario == "wrong-bundle-generation" {
					w.Header().Set("Cache-Control", "no-cache")
				}
				w.Write(data)
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60}, false)
			view, catalogs, e := s.prepareGoModuleView(ctx, i, repo, c.Module, false)
			if e != nil || latestGoVersion(view.Versions) != c.Version {
				t.Fatal("prepare exact latest", e)
			}
			a, e := s.resolve(ctx, i, repo, c.Prefix()+".info", false)
			if e != nil {
				t.Fatal(e)
			}
			a.goLatest, a.goMetadataAdmissions = true, catalogs
			if _, e = s.guardResolved(ctx, i, a); e != nil {
				t.Fatal("initial catalog/bundle admission rejected", scenario, e)
			}
			query, p := "", catalogPath
			want := error(nil)
			switch scenario {
			case "catalog-refresh-new":
				newer.Store(true)
				if _, e = s.resolveProxy(ctx, i, repo, catalogPath, true); e != nil {
					t.Fatal(e)
				}
				want = store.ErrConflict
			case "catalog-expired":
				a.goMetadataAdmissions = nil
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository='source' AND path=$1`
				want = store.ErrGoModuleCacheExpired
			case "bundle-expired":
				a.admissions = nil
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository='source' AND path<>$1`
				want = store.ErrGoModuleCacheExpired
			case "catalog-denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='source' AND path=$1`
				want = store.ErrDenied
			case "bundle-denied":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='source' AND path=$1`
				p, want = c.Prefix()+".zip", store.ErrDenied
			case "wrong-catalog-generation":
				a.goMetadataAdmissions[0].Generation++
				want = store.ErrGoModuleCacheExpired
			case "wrong-bundle-generation":
				a.admissions[0].Generation++
				want = store.ErrGoModuleCacheExpired
			}
			if query != "" {
				if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query, p); return e }); e != nil {
					t.Fatal(e)
				}
			}
			current, e := s.guardResolved(ctx, i, a)
			if !errors.Is(e, want) {
				t.Fatal("latest mixed current catalog and bundle state", scenario, e, want)
			}
			if want != nil && (current.Digest != "" || len(current.Metadata) != 0) {
				t.Fatal("failed mutable selection returned package bytes")
			}
			if want == nil && current.Digest != a.artifact.Digest {
				t.Fatal("current latest changed original info bytes")
			}
		})
	}
}
