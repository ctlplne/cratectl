//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleOriginBundlePublicationUsesCurrentTransactionFences(t *testing.T) {
	for _, scenario := range []string{"complete", "source", "lease"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, token, i := schemaServer(t)
			ctx := context.Background()
			c, files := goOriginBytes(t)
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				if kind == "zip" && scenario != "complete" {
					e := s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
						query := `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`
						if scenario == "lease" {
							query = `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='source'`
						}
						_, e := tx.Exec(ctx, query)
						return e
					})
					if e != nil {
						t.Error("change fence during owned transfer", e)
						w.WriteHeader(500)
						return
					}
				}
				data, ok := files[kind]
				if !ok || r.URL.Path != "/go/source/"+c.Prefix()+"."+kind {
					t.Error("unexpected origin request")
					w.WriteHeader(400)
					return
				}
				w.Write(data)
			}))
			s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			settings, _ := json.Marshal(store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/go/source/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60, StaleSeconds: 40}})
			// Unsupported lab-only row through ordinary tenant runtime SQL. Public
			// Go proxy creation and serving remain rejected; no owner/BYPASS grant.
			if e := s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings)VALUES($1,'source','go','proxy',true,'restricted',$2)`, i.Tenant, settings)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			repo, e := s.DB.Repository(ctx, i, "source")
			if e != nil {
				t.Fatal(e)
			}
			lease, e := s.DB.AcquireRetrieval(ctx, i, repo.Name, c.Prefix()+".zip", "owned-origin-bundle", false)
			if e != nil || !lease.Acquired {
				t.Fatal("acquire common fenced retrieval", e)
			}
			result, e := s.fetchGoModuleBundle(ctx, i, repo, lease)
			if e != nil || result.GoModule == nil || calls.Load() != 3 {
				t.Fatal("fetch complete owned bundle", e, calls.Load())
			}
			e = s.DB.CompleteRetrieval(ctx, i, lease, result)
			want := error(nil)
			n := 3
			switch scenario {
			case "source":
				want, n = store.ErrSourceChanged, 0
			case "lease":
				want, n = store.ErrLeaseLost, 0
			}
			if !errors.Is(e, want) {
				t.Fatal("completion did not enforce current transfer fence", scenario, e)
			}
			if e := s.DB.Tx(ctx, i, false, func(tx pgx.Tx) error {
				for _, query := range []string{`SELECT count(*) FROM cratectl.artifacts WHERE repository='source'`, `SELECT count(*) FROM cratectl.jobs WHERE queue='integrity'`} {
					var count int
					if e := tx.QueryRow(ctx, query).Scan(&count); e != nil {
						return e
					}
					if count != n {
						t.Error("partial or unfenced publication references/intents", count, n)
					}
				}
				var ready int
				if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='proxy.retrieval.ready'`).Scan(&ready); e != nil {
					return e
				}
				if ready != n/3 {
					t.Error("ready event differs from atomic publication", ready, n/3)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if scenario == "complete" {
				for _, a := range result.GoModule.Objects {
					if _, e := s.DB.Artifact(ctx, i, repo.Name, a.Path); !errors.Is(e, store.ErrDenied) {
						t.Fatal("unassessed network intake became approved", e)
					}
					cache, e := s.DB.Retrieval(ctx, i, repo.Name, a.Path)
					if e != nil || !cache.Fresh() || cache.ValidationRoot != lease.Path || cache.ValidationGeneration != lease.Generation {
						t.Fatal("retrieved member lacks common root validation receipt", e)
					}
				}
			}
			if w := goHTTP(t, s, token, "GET", "/go/source/"+c.Prefix()+".zip", nil); w.Code != 405 {
				t.Fatal("internal transaction fixture enabled incomplete public proxy", w.Code)
			}
		})
	}
}
