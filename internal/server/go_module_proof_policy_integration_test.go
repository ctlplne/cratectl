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

	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func expireServerGoProofReceipt(t *testing.T, dsn, tenant string) {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "cratectl_init_") {
		t.Fatal("proof clock fault requires an owned disposable database")
	}
	ctx := context.Background()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	tag, err := owner.Exec(ctx, `UPDATE cratectl.go_module_checksum_receipts SET created_at=clock_timestamp()-interval '1 hour' WHERE tenant=$1 AND repository='source'`, tenant)
	if err != nil || tag.RowsAffected() == 0 {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumProofPolicyRefreshesExpiredHitWithoutServingExpiredStale(t *testing.T) {
	for _, scenario := range []string{"retained-old", "max-age-recent", "max-age-expired", "max-age-concurrent", "expires-after-package-readback", "origin-unavailable", "authority-unavailable", "proof-denied"} {
		t.Run(scenario, func(t *testing.T) {
			s, d, _, i := schemaServer(t)
			ctx := context.Background()
			c, files := goOriginBytes(t)
			public := goChecksumPublic(t)
			var fail atomic.Bool
			var mutex sync.Mutex
			calls := map[string]int{}
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mutex.Lock()
				calls[r.URL.Path]++
				mutex.Unlock()
				w.Header().Set("Cache-Control", "max-age=60")
				path, checksum := strings.CutPrefix(r.URL.Path, "/checksum")
				if fail.Load() && (scenario == "authority-unavailable" && checksum || scenario == "origin-unavailable" && !checksum) {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				data, ok := public.Responses[path]
				if !checksum {
					data, ok = files[strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")]
				}
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Write(data)
			}))
			repo := goChecksumCallerRepository(t, s, i, origin.URL, public, false)
			if scenario != "retained-old" {
				repo.Settings.GoChecksumAuthority.ProofPolicy = &store.GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}
			}
			raw, err := json.Marshal(repo.Settings)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE cratectl.repositories SET settings=$1 WHERE name='source'`, raw)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			first, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
			if err != nil {
				t.Fatal("initial complete independently verified bundle", err)
			}
			if scenario != "max-age-recent" && scenario != "expires-after-package-readback" {
				expireServerGoProofReceipt(t, d.OwnerDSN, i.Tenant)
			}
			if scenario == "proof-denied" {
				if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE starts_with(path,'go-checksum/')`)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			fail.Store(true)
			var second resolvedArtifact
			if scenario == "max-age-concurrent" {
				type outcome struct {
					resolved resolvedArtifact
					err      error
				}
				outcomes := make(chan outcome, 12)
				start := make(chan struct{})
				for n := 0; n < 12; n++ {
					go func() {
						<-start
						resolved, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
						outcomes <- outcome{resolved: resolved, err: err}
					}()
				}
				close(start)
				for n := 0; n < 12; n++ {
					result := <-outcomes
					if result.err != nil || result.resolved.artifact.Digest != first.artifact.Digest {
						t.Fatal("concurrent expired proof refresh", result.err)
					}
					if second.artifact.Digest == "" || result.resolved.cache == "filled" {
						second = result.resolved
					}
				}
				err = nil
			} else {
				second, err = s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
			}
			failed := scenario == "origin-unavailable" || scenario == "authority-unavailable" || scenario == "proof-denied"
			if failed {
				if err == nil || second.artifact.Digest != "" {
					t.Fatal("expired proof or denied evidence granted package bytes", scenario, err)
				}
				if scenario == "origin-unavailable" && !errors.Is(err, store.ErrGoChecksumProofExpired) {
					t.Fatal("ordinary origin stale bypassed proof age policy", err)
				}
				if scenario == "proof-denied" && !errors.Is(err, store.ErrDenied) {
					t.Fatal("denied proof became refreshable age error", err)
				}
			} else {
				if err != nil || second.artifact.Digest != first.artifact.Digest {
					t.Fatal("explicit proof policy lost immutable bytes", scenario, err)
				}
				object, err := s.Blobs.OpenVerified(ctx, i.Tenant, second.artifact.Digest, second.artifact.Size)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, object)
				object.Close()
				if err != nil {
					t.Fatal(err)
				}
				wantGuard := error(nil)
				if scenario == "expires-after-package-readback" {
					expireServerGoProofReceipt(t, d.OwnerDSN, i.Tenant)
					wantGuard = store.ErrGoChecksumProofExpired
				}
				if _, err = s.guardResolved(ctx, i, second); !errors.Is(err, wantGuard) {
					t.Fatal("current proof policy after actual package readback", err, wantGuard)
				}
			}
			state, stateErr := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", 0)
			if stateErr != nil {
				t.Fatal(stateErr)
			}
			if (scenario == "max-age-expired" || scenario == "max-age-concurrent") && (state.Generation != 2 || state.ValidationGeneration != 2 || second.cache != "filled") {
				t.Fatal("expired fresh hit did not complete exactly one governed refresh", state.Generation, state.ValidationGeneration, second.cache)
			}
			if scenario == "origin-unavailable" && !state.StalePermitted() {
				t.Fatal("fixture must permit ordinary-origin stale for checksum-age refusal", state.LastError)
			}
			if scenario == "authority-unavailable" && (state.State != "failed" || state.LastError != "upstream_checksum_unverified" || state.StalePermitted()) {
				t.Fatal("unavailable authority granted stale or lost classified failure", state.LastError)
			}
			checkpoint, checkpointErr := s.DB.GoModuleChecksumCheckpoint(ctx, i, repo.Name, 0)
			if checkpointErr != nil || checkpoint.Revision != 2 || !bytes.Equal(checkpoint.Checkpoint, public.Advanced) {
				t.Fatal("proof age refresh reset or advanced identical signed trust", checkpointErr)
			}
			wantReceipts := 1
			if scenario == "max-age-expired" || scenario == "max-age-concurrent" {
				wantReceipts = 2
			}
			if err := s.DB.Tx(ctx, i, false, func(tx pgx.Tx) error {
				var receipts int
				err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.go_module_checksum_receipts WHERE repository='source'`).Scan(&receipts)
				if err == nil && receipts != wantReceipts {
					t.Error("proof age refresh admitted missing or partial receipt", receipts, wantReceipts)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			mutex.Lock()
			packageCalls, checksumCalls := 0, 0
			for path, count := range calls {
				if strings.HasPrefix(path, "/checksum/") {
					checksumCalls += count
				} else {
					packageCalls += count
				}
			}
			mutex.Unlock()
			if scenario == "retained-old" || scenario == "max-age-recent" || scenario == "expires-after-package-readback" || scenario == "proof-denied" {
				if packageCalls != 3 || checksumCalls != 2 || state.Generation != 1 {
					t.Fatal("retained/recent/denied proof unexpectedly contacted a source or replaced evidence", packageCalls, checksumCalls, state.Generation)
				}
			} else if (scenario == "max-age-expired" || scenario == "max-age-concurrent") && (packageCalls != 6 || checksumCalls != 4) {
				t.Fatal("expired proof refresh duplicated package or authority transfers", packageCalls, checksumCalls)
			}
			if len(s.fillSlots) != 0 {
				t.Fatal("proof age refresh leaked a transfer slot")
			}
		})
	}
}
