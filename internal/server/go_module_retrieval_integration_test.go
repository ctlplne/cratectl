//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

// A lab-only proxy row exercises internal callers without enabling the public
// Go proxy contract. All application work uses the ordinary tenant runtime.
func goCallerRepository(t *testing.T, s *Server, i store.Identity, url string, cache store.CacheSettings, review bool) store.Repository {
	t.Helper()
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	settings, e := json.Marshal(store.RepositorySettings{Upstream: &upstream.Config{URL: url + "/go/source/", Networks: []string{"127.0.0.1/32"}}, Cache: cache})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DB.Tx(context.Background(), i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(context.Background(), `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings)VALUES($1,'source','go','proxy',$2,'restricted',$3)`, i.Tenant, review, settings)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	r, e := s.DB.Repository(context.Background(), i, "source")
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func goCallerCounts(t *testing.T, s *Server, i store.Identity, want int, intents ...int) {
	t.Helper()
	if e := s.DB.Tx(context.Background(), i, false, func(tx pgx.Tx) error {
		for index, query := range []string{`SELECT count(*) FROM cratectl.artifacts WHERE repository='source'`, `SELECT count(*) FROM cratectl.jobs WHERE queue='integrity' AND payload->>'repository'='source'`} {
			expected := want
			if index == 1 && len(intents) != 0 {
				expected = intents[0]
			}
			var n int
			if e := tx.QueryRow(context.Background(), query).Scan(&n); e != nil {
				return e
			}
			if n != expected {
				t.Errorf("partial caller publication/intent: got%d want%d", n, expected)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if len(s.fillSlots) != 0 {
		t.Fatal("caller leaked a process transfer slot")
	}
}

func TestGoModuleProxyCallerCoalescesRepresentationsUnderOneLease(t *testing.T) {
	s, _, _, i := schemaServer(t)
	c, files := goOriginBytes(t)
	var calls atomic.Int32
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
		data, ok := files[kind]
		if !ok {
			t.Error("unexpected caller representation")
			w.WriteHeader(400)
			return
		}
		w.Write(data)
	}))
	repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 12; n++ {
		kind := []string{"info", "mod", "zip"}[n%3]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			a, e := s.resolve(ctx, i, repo, c.Prefix()+"."+kind, false)
			if e != nil {
				t.Error("coalesced caller", e)
				return
			}
			if a.artifact.Path != c.Prefix()+"."+kind || a.artifact.Digest != crypt.Digest(files[kind]) {
				t.Error("caller returned a different representation")
			}
			f, e := s.Blobs.OpenVerified(ctx, i.Tenant, a.artifact.Digest, a.artifact.Size)
			if e != nil {
				t.Error(e)
				return
			}
			got, e := io.ReadAll(f)
			f.Close()
			if e != nil || !bytes.Equal(got, files[kind]) {
				t.Error("caller lost original upstream bytes", e)
			}
			if _, e = s.guardResolved(ctx, i, a); e != nil {
				t.Error("coalesced final guard", e)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 3 {
		t.Fatal("representations used separate bundle fills", calls.Load())
	}
	goCallerCounts(t, s, i, 3)
	for _, kind := range []string{"info", "mod", "zip"} {
		r, e := s.DB.Retrieval(ctx, i, "source", c.Prefix()+"."+kind)
		if e != nil || r.ValidationRoot != c.Prefix()+".zip" || r.ValidationGeneration != 1 || r.State != "ready" {
			t.Fatal("caller lacks one common successful validation", kind, e)
		}
	}
}

func TestGoModuleProxyCallerRecordsFailuresWithoutPartialPublication(t *testing.T) {
	for _, scenario := range []string{"missing", "gone-zero", "missing-mod", "invalid-info", "transient", "auth", "checksum", "queue", "source", "lease", "grant", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			s, d, token, admin := schemaServer(t)
			i := admin
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, files := goOriginBytes(t)
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				switch scenario {
				case "missing":
					w.Header().Set("Cache-Control", "max-age=7")
					w.WriteHeader(404)
					return
				case "gone-zero":
					w.Header().Set("Cache-Control", "no-cache")
					w.WriteHeader(410)
					return
				case "missing-mod":
					if kind == "mod" {
						w.WriteHeader(404)
						return
					}
				case "invalid-info":
					w.Write([]byte(`{"Version":"v2.0.0"}`))
					return
				case "transient":
					w.WriteHeader(503)
					return
				case "auth":
					w.WriteHeader(401)
					return
				case "cancel":
					cancel()
					<-r.Context().Done()
					return
				}
				if kind == "zip" && (scenario == "source" || scenario == "lease" || scenario == "grant") {
					query := `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`
					if scenario == "lease" {
						query = `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='source'`
					}
					if scenario == "grant" {
						query = `UPDATE cratectl.repository_grants SET can_read=false WHERE repository='source' AND actor='caller-reader'`
					}
					if e := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error { _, e := tx.Exec(context.Background(), query); return e }); e != nil {
						t.Error("change live caller fence", e)
						w.WriteHeader(500)
						return
					}
				}
				data, ok := files[kind]
				if !ok {
					t.Error("unexpected caller path")
					w.WriteHeader(400)
					return
				}
				w.Write(data)
			}))
			repo := goCallerRepository(t, s, admin, origin.URL, store.CacheSettings{FreshSeconds: 60, NegativeSeconds: 30, RequireChecksum: scenario == "checksum"}, false)
			if scenario == "queue" {
				_, e := s.DB.SetQueuePolicy(ctx, admin, "owned-caller-capacity", "owned-caller-capacity", store.QueuePolicy{Queue: "integrity", Capacity: 2, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2})
				if e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "grant" {
				credential := "owned-inert-caller-reader-credential"
				if e := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "caller-reader", "reader", credential, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				var e error
				i, e = s.DB.Authenticate(ctx, credential)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'source','caller-reader',true,false)`, admin.Tenant)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			a, e := s.resolve(ctx, i, repo, c.Prefix()+".mod", false)
			want := errUpstream
			switch scenario {
			case "missing", "gone-zero":
				want = store.ErrNotFound
			case "source":
				want = store.ErrSourceChanged
			case "lease":
				want = store.ErrLeaseLost
			case "grant":
				want = store.ErrDenied
			case "queue":
				want = store.ErrQueueFull
			case "cancel":
				want = context.Canceled
			}
			if !errors.Is(e, want) || a.artifact.Digest != "" {
				t.Fatal("caller failure became success or wrong boundary", scenario, e, want)
			}
			goCallerCounts(t, s, admin, 0)
			state, e := s.DB.Retrieval(context.Background(), admin, "source", c.Prefix()+".zip")
			if e != nil {
				t.Fatal(e)
			}
			wantState := "failed"
			if scenario == "missing" || scenario == "gone-zero" {
				wantState = "negative"
			}
			if scenario == "source" || scenario == "lease" || scenario == "grant" {
				wantState = "fetching"
			}
			if state.State != wantState {
				t.Fatal("failure lost durable retrieval state", state.State, wantState)
			}
			if scenario == "checksum" && calls.Load() != 0 {
				t.Fatal("checksum requirement contacted unchecked origin")
			}
			if scenario == "queue" && (state.LastError != "queue_capacity" || state.LeaseUntil.After(state.Now)) {
				t.Fatal("queue rollback lost common classification or retained a live lease")
			}
			if scenario == "transient" && state.LastError != "transient_upstream_failure" {
				t.Fatal("temporary origin failure lost classification")
			}
			if scenario == "gone-zero" && state.Fresh() {
				t.Fatal("no-cache negative became reusable")
			}
			if scenario == "missing" {
				if _, e = s.resolve(context.Background(), admin, repo, c.Prefix()+".info", false); !errors.Is(e, store.ErrNotFound) || calls.Load() != 1 {
					t.Fatal("fresh negative lost canonical coalescing", e, calls.Load())
				}
			}
			if scenario == "queue" {
				if _, e = s.DB.SetQueuePolicy(context.Background(), admin, "owned-caller-capacity-recovery", "owned-caller-capacity-recovery", store.QueuePolicy{Queue: "integrity", Capacity: 8, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); e != nil {
					t.Fatal(e)
				}
				if recovered, e := s.resolve(context.Background(), admin, repo, c.Prefix()+".info", false); e != nil || recovered.artifact.Digest == "" {
					t.Fatal("capacity repair did not recover canonical bundle caller", e)
				}
				current, e := s.DB.Retrieval(context.Background(), admin, "source", c.Prefix()+".zip")
				if e != nil || current.Generation <= state.Generation || current.State != "ready" {
					t.Fatal("queue recovery reused old lease generation", e)
				}
				goCallerCounts(t, s, admin, 3)
			}
			if w := goHTTP(t, s, token, "GET", "/go/source/"+c.Prefix()+".zip", nil); w.Code != 405 {
				t.Fatal("internal caller enabled public proxy", w.Code)
			}
		})
	}
}

func TestGoModuleProxyCallerOnlyAdmitsExplicitTransientStale(t *testing.T) {
	for _, scenario := range []string{"transient", "auth", "invalid", "missing-known", "no-cache"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			ctx := context.Background()
			c, files := goOriginBytes(t)
			var refresh atomic.Bool
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				if refresh.Load() {
					switch scenario {
					case "transient":
						w.WriteHeader(503)
						return
					case "auth":
						w.WriteHeader(401)
						return
					case "invalid":
						w.Write([]byte("invalid"))
						return
					case "missing-known":
						w.WriteHeader(404)
						return
					}
				}
				if scenario == "no-cache" {
					w.Header().Set("Cache-Control", "no-cache")
				}
				w.Write(files[kind])
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60, NegativeSeconds: 60}, false)
			first, e := s.resolve(ctx, i, repo, c.Prefix()+".info", false)
			if e != nil {
				t.Fatal("initial complete bundle", e)
			}
			if _, e = s.guardResolved(ctx, i, first); e != nil {
				t.Fatal("initial final selection", e)
			}
			refresh.Store(true)
			a, e := s.resolve(ctx, i, repo, c.Prefix()+".mod", true)
			if scenario == "transient" || scenario == "no-cache" {
				if e != nil || a.artifact.Digest != crypt.Digest(files["mod"]) {
					t.Fatal("admissible exact bundle rejected", e)
				}
				if scenario == "transient" && a.cache != "stale" {
					t.Fatal("temporary refresh did not mark stale")
				}
				if _, e = s.guardResolved(ctx, i, a); e != nil {
					t.Fatal("request admission lost sibling/cache guard", e)
				}
				if scenario == "no-cache" {
					a.admissions = nil
					if _, e = s.guardResolved(ctx, i, a); !errors.Is(e, store.ErrGoModuleCacheExpired) {
						t.Fatal("zero-age result escaped request admission", e)
					}
				}
			} else {
				want := errUpstream
				if scenario == "missing-known" {
					want = store.ErrDenied
				}
				if !errors.Is(e, want) || a.artifact.Digest != "" {
					t.Fatal("hard failure admitted stale/absence", scenario, e)
				}
			}
			intents := 3
			if scenario == "no-cache" {
				intents = 6
			}
			goCallerCounts(t, s, i, 3, intents)
		})
	}
}

func TestGoModuleProxyGroupCarriesOnlyCurrentNegativeFallback(t *testing.T) {
	s, _, token, i := schemaServer(t)
	ctx := context.Background()
	c, files := goOriginBytes(t)
	var calls atomic.Int32
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(404)
	}))
	repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{NegativeSeconds: 30}, false)
	mavenRepositories(t, s, i, store.Repository{Name: "lower", Format: "go", Access: "restricted"}, store.Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", Settings: store.RepositorySettings{Members: []string{"source", "lower"}}})
	if w := goHTTP(t, s, token, "PUT", "/go/lower/"+c.Prefix()+".zip", files["zip"]); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	group, e := s.DB.Repository(ctx, i, "combined")
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.resolve(ctx, i, group, c.Prefix()+".mod", false)
	if e != nil || a.source.Name != "lower" || len(a.admissions) != 1 || calls.Load() != 1 {
		t.Fatal("group lost exact negative fallback admission", e, calls.Load())
	}
	if _, e = s.guardResolved(ctx, i, a); e != nil {
		t.Fatal("same-request negative fallback rejected", e)
	}
	if _, e = s.resolve(ctx, i, repo, c.Prefix()+".info", true); !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
	if _, e = s.guardResolved(ctx, i, a); !errors.Is(e, store.ErrGoModuleCacheExpired) {
		t.Fatal("old negative authorized changed-generation fallback", e)
	}
}

func TestGoModuleProxyCallerRenewsAndCancelsOnSourceLoss(t *testing.T) {
	for _, scenario := range []string{"renew", "source-loss"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			s.ProxyLease = 3 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, files := goOriginBytes(t)
			started, release := make(chan struct{}), make(chan struct{})
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				if kind == "info" {
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				w.Write(files[kind])
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60}, false)
			finished := make(chan error, 1)
			go func() { _, e := s.resolve(ctx, i, repo, c.Prefix()+".zip", false); finished <- e }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("owned transfer did not start")
			}
			first, e := s.DB.Retrieval(ctx, i, "source", c.Prefix()+".zip")
			if e != nil {
				t.Fatal(e)
			}
			if scenario == "source-loss" {
				if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			} else {
				for {
					current, e := s.DB.Retrieval(ctx, i, "source", c.Prefix()+".zip")
					if e != nil {
						t.Fatal(e)
					}
					if current.LeaseUntil.After(first.LeaseUntil) {
						break
					}
					select {
					case <-time.After(25 * time.Millisecond):
					case <-ctx.Done():
						t.Fatal("active caller lease was not renewed")
					}
				}
				close(release)
			}
			select {
			case e = <-finished:
				if scenario == "source-loss" {
					if !errors.Is(e, store.ErrSourceChanged) {
						t.Fatal("heartbeat failed to cancel changed source", e)
					}
					goCallerCounts(t, s, i, 0)
				} else {
					if e != nil {
						t.Fatal("renewed caller failed", e)
					}
					goCallerCounts(t, s, i, 3)
				}
			case <-ctx.Done():
				t.Fatal("caller did not finish after renewal/source loss")
			}
		})
	}
}

func TestGoModuleProxyCallerCatalogKeepsAdvertisementSeparateFromApproval(t *testing.T) {
	for _, scenario := range []string{"fresh", "no-cache", "missing", "invalid"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			ctx := context.Background()
			c, _ := goOriginBytes(t)
			raw := []byte("v1.1.0\r\nv1.0.0\n")
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/go/source/"+strings.TrimSuffix(c.Prefix(), "/@v/"+c.Version)+"/@v/list" {
					t.Error("catalog escaped configured module source")
					w.WriteHeader(400)
					return
				}
				if scenario == "missing" {
					w.WriteHeader(404)
					return
				}
				if scenario == "no-cache" {
					w.Header().Set("Cache-Control", "no-cache")
				}
				if scenario == "invalid" {
					w.Write([]byte("v1.0.0\nbroken\n"))
					return
				}
				w.Write(raw)
			}))
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, NegativeSeconds: 30, RequireChecksum: true}, true)
			p := store.GoModuleCatalogPath(c.Module)
			a, e := s.resolve(ctx, i, repo, p, false)
			if scenario == "invalid" || scenario == "missing" {
				want := errUpstream
				if scenario == "missing" {
					want = store.ErrNotFound
				}
				if !errors.Is(e, want) || a.artifact.Digest != "" {
					t.Fatal("catalog failure published partial names", e)
				}
				goCallerCounts(t, s, i, 0)
				return
			}
			if e != nil || a.artifact.Digest != crypt.Digest(raw) || a.artifact.Decision != "unassessed" {
				t.Fatal("catalog lost original bytes or granted package approval", e)
			}
			goCallerCounts(t, s, i, 1)
			view, e := s.DB.GoModuleView(ctx, i, repo.Name, c.Module, 100, 1<<20, a.admissions...)
			if e != nil || len(view.Versions) != 0 || !view.Known {
				t.Fatal("advertisement bypassed require-review", e)
			}
			if scenario == "no-cache" {
				if _, e = s.DB.GoModuleView(ctx, i, repo.Name, c.Module, 100, 1<<20); !errors.Is(e, store.ErrGoModuleCacheExpired) {
					t.Fatal("zero-age advertisement became reusable", e)
				}
			}
		})
	}
}
