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
	"golang.org/x/mod/module"
)

func TestGoModuleLatestPreparationAndServingUseCurrentHintWithOldCachedPseudos(t *testing.T) {
	for _, scenario := range []string{"cached-newer", "unknown-hint", "review", "negative-known", "negative-unknown", "tagged-no-hint", "list-no-hint", "zero-hint", "wrong-hint-generation", "changed-hint", "new-tag", "hint-expired", "group-change", "source-change", "new-denial", "hint-malformed"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, token, i := schemaServer(t)
			ctx := context.Background()
			base, _ := goOriginBytes(t)
			current := "v0.0.0-20260102030405-0123456789ab"
			old := "v0.0.0-20260103030405-0123456789ab"
			changed := "v0.0.0-20260101030405-0123456789ab"
			bundles := map[string]map[string][]byte{}
			for _, version := range []string{current, old, changed, "v1.0.0"} {
				c := gomodule.Coordinate{Module: base.Module, Version: version}
				zip, mod := goPublicationFixture(t, c, "owned latest "+version)
				instant := goFixtureInstant
				if module.IsPseudoVersion(version) {
					stamp, e := module.PseudoVersionTime(version)
					if e != nil {
						t.Fatal(e)
					}
					instant = stamp.UTC().Format("2006-01-02T15:04:05Z")
				}
				info, e := gomodule.VersionInfo(c, instant)
				if e != nil {
					t.Fatal(e)
				}
				bundles[version] = map[string][]byte{"zip": zip, "mod": mod, "info": info}
			}
			escaped := strings.TrimPrefix(store.GoModuleCatalogPath(base.Module), "go-catalog/")
			var hints atomic.Int32
			var change atomic.Bool
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := strings.TrimPrefix(r.URL.Path, "/go/source/"+escaped+"/")
				if p == "@v/list" {
					if scenario == "tagged-no-hint" {
						w.Write([]byte("v1.0.0\n"))
					} else {
						w.WriteHeader(200)
					}
					return
				}
				if p == "@latest" {
					hints.Add(1)
					if scenario == "list-no-hint" || scenario == "tagged-no-hint" {
						t.Error("unneeded optional latest endpoint was contacted")
						w.WriteHeader(500)
						return
					}
					if scenario == "negative-known" || scenario == "negative-unknown" {
						w.WriteHeader(404)
						return
					}
					if scenario == "hint-malformed" {
						w.Write([]byte(`{"Version":"v2.0.0"}`))
						return
					}
					if scenario == "zero-hint" || scenario == "wrong-hint-generation" {
						w.Header().Set("Cache-Control", "no-cache")
					}
					version := current
					if change.Load() {
						version = changed
					}
					w.Write(bundles[version]["info"])
					return
				}
				if rest, ok := strings.CutPrefix(p, "@v/"); ok {
					for version, files := range bundles {
						for kind, data := range files {
							if rest == version+"."+kind {
								w.Write(data)
								return
							}
						}
					}
				}
				t.Error("latest request escaped fixed configured representations")
				w.WriteHeader(400)
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60, NegativeSeconds: 30}, scenario == "review")
			mavenRepositories(t, s, i, store.Repository{Name: "combined", Format: "go", Mode: "group", Settings: store.RepositorySettings{Members: []string{"source"}}})
			group, e := s.DB.Repository(ctx, i, "combined")
			if e != nil {
				t.Fatal(e)
			}
			if scenario != "unknown-hint" && scenario != "negative-unknown" {
				c := gomodule.Coordinate{Module: base.Module, Version: old}
				_, e := s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
				if scenario == "review" {
					if !errors.Is(e, store.ErrDenied) {
						t.Fatal("unassessed old cache was approved", e)
					}
				} else if e != nil {
					t.Fatal("populate original cached pseudo", e)
				}
			}
			path := "/go/combined/" + escaped
			if scenario == "list-no-hint" {
				for _, method := range []string{"GET", "HEAD"} {
					w := goHTTP(t, s, token, method, path+"/@v/list", nil)
					if w.Code != 200 || w.Body.Len() != 0 || hints.Load() != 0 {
						t.Fatal("ordinary list depended on optional latest", w.Code, hints.Load())
					}
				}
				return
			}
			view, metadata, e := s.prepareGoModuleDiscovery(ctx, i, group, base.Module, false, true)
			if scenario == "hint-malformed" {
				if !errors.Is(e, errUpstream) || view.Known || len(view.Versions) != 0 || len(metadata) != 0 {
					t.Fatal("invalid hint admitted cached pseudo history", e)
				}
				return
			}
			if e != nil {
				t.Fatal("prepare current latest", e)
			}
			if scenario == "review" || scenario == "negative-known" || scenario == "negative-unknown" {
				want := store.ErrDenied
				status := 403
				if scenario == "negative-unknown" {
					want, status = store.ErrNotFound, 404
				}
				if _, e := latestGoSelection(view); !errors.Is(e, want) {
					t.Fatal("latest lost known-blocked/absent distinction", scenario, e, want)
				}
				w := goHTTP(t, s, token, "GET", path+"/@latest", nil)
				if w.Code != status || w.Header().Get("ETag") != "" || bytes.Contains(w.Body.Bytes(), []byte(`"Version"`)) {
					t.Fatal("blocked/absent hint leaked cached latest", scenario, w.Code)
				}
				return
			}
			version, e := latestGoSelection(view)
			if e != nil {
				t.Fatal(e)
			}
			expected := current
			if scenario == "tagged-no-hint" {
				expected = "v1.0.0"
			}
			if version != expected {
				t.Fatal("latest chose cached pseudo rather than current hint/tag", version, expected)
			}
			c := gomodule.Coordinate{Module: base.Module, Version: version}
			a, e := s.resolve(ctx, i, group, c.Prefix()+".info", false)
			if e != nil {
				t.Fatal(e)
			}
			a.goLatest, a.goMetadataAdmissions = true, metadata
			f, e := s.Blobs.OpenVerified(ctx, i.Tenant, a.artifact.Digest, a.artifact.Size)
			if e != nil {
				t.Fatal(e)
			}
			f.Close()
			want := error(nil)
			status := 200
			query := ""
			switch scenario {
			case "changed-hint":
				change.Store(true)
				if _, e = s.resolve(ctx, i, repo, store.GoModuleLatestPath(base.Module), true); e != nil {
					t.Fatal(e)
				}
				want, status = store.ErrConflict, 409
			case "new-tag":
				tag := gomodule.Coordinate{Module: base.Module, Version: "v1.0.0"}
				if _, e = s.resolve(ctx, i, repo, tag.Prefix()+".zip", false); e != nil {
					t.Fatal(e)
				}
				want, status = store.ErrConflict, 409
			case "wrong-hint-generation":
				for n := range a.goMetadataAdmissions {
					if strings.HasPrefix(a.goMetadataAdmissions[n].Path, "go-latest/") {
						a.goMetadataAdmissions[n].Generation++
					}
				}
				want, status = store.ErrGoModuleCacheExpired, 503
			case "hint-expired":
				var keep []store.NativeAdmission
				for _, admission := range a.goMetadataAdmissions {
					if !strings.HasPrefix(admission.Path, "go-latest/") {
						keep = append(keep, admission)
					}
				}
				a.goMetadataAdmissions = keep
				query = `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository='source' AND starts_with(path,'go-latest/')`
				want, status = store.ErrGoModuleCacheExpired, 503
			case "group-change":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='combined'`
				want, status = store.ErrSourceChanged, 503
			case "source-change":
				query = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`
				want, status = store.ErrSourceChanged, 503
			case "new-denial":
				query = `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='source' AND path=$1`
				want, status = store.ErrDenied, 403
			}
			if query != "" {
				if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
					var args []any
					if scenario == "new-denial" {
						args = []any{c.Prefix() + ".zip"}
					}
					_, e := tx.Exec(ctx, query, args...)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = s.guardResolved(ctx, i, a); !errors.Is(e, want) {
				t.Fatal("final latest guard lost current hint/source/bundle", scenario, e, want)
			}
			w := httptest.NewRecorder()
			s.serveResolvedArtifact(w, httptest.NewRequest("GET", path+"/@latest", nil), i, a)
			if w.Code != status {
				t.Fatal("final latest serving status", scenario, w.Code, status)
			}
			if want != nil && (w.Header().Get("ETag") != "" || w.Header().Get("X-Checksum-Sha256") != "" || bytes.Contains(w.Body.Bytes(), []byte(`"Version"`))) {
				t.Fatal("superseded latest escaped final guard")
			}
			if want == nil && !bytes.Equal(w.Body.Bytes(), bundles[version]["info"]) {
				t.Fatal("latest serving changed original selected info bytes")
			}
			if scenario == "cached-newer" || scenario == "tagged-no-hint" {
				for _, method := range []string{"GET", "HEAD"} {
					w := goHTTP(t, s, token, method, path+"/@latest", nil)
					if w.Code != 200 || method == "GET" && !bytes.Equal(w.Body.Bytes(), bundles[version]["info"]) || method == "HEAD" && w.Body.Len() != 0 {
						t.Fatal("actual latest adapter lost current version", method, w.Code)
					}
				}
			}
			if scenario == "tagged-no-hint" && hints.Load() != 0 {
				t.Fatal("tagged selection contacted optional hint")
			}
			if scenario == "zero-hint" {
				a.goMetadataAdmissions = nil
				if _, e = s.guardResolved(ctx, i, a); !errors.Is(e, store.ErrGoModuleCacheExpired) {
					t.Fatal("zero-age hint escaped current metadata admission", e)
				}
			}
		})
	}
}
