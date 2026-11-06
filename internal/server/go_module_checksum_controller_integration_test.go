//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"github.com/jackc/pgx/v5"
)

func goChecksumCallerRepository(t *testing.T, s *Server, i store.Identity, url string, f publicGoChecksum, review bool) store.Repository {
	t.Helper()
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	r := goCallerRepository(t, s, i, url, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60, RequireChecksum: true}, review)
	r.Settings.GoChecksumAuthority = &store.GoChecksumAuthority{Endpoint: upstream.Config{URL: url + "/checksum/", Networks: []string{"127.0.0.1/32"}}, VerifierKey: f.Key, InitialCheckpoint: f.Initial}
	raw, err := json.Marshal(r.Settings)
	if err != nil {
		t.Fatal(err)
	}
	// Initial lab-only configuration before any package lease. Public proxy
	// creation/routing remains gated until complete native client journeys.
	if err = s.DB.Tx(context.Background(), i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE cratectl.repositories SET settings=$1 WHERE name='source'`, raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err = s.DB.Repository(context.Background(), i, r.Name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func checksumControllerFiles(t *testing.T, c gomodule.Coordinate, payload string) map[string][]byte {
	t.Helper()
	mod := []byte("module " + c.Module + "\n\ngo 1.26.0\n")
	info, err := gomodule.VersionInfo(c, "2026-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	z := zip.NewWriter(&body)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"go.mod", mod}, {"assets/inert.txt", []byte(payload)}} {
		w, err := z.Create(c.Module + "@" + c.Version + "/" + entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"zip": body.Bytes(), "mod": mod, "info": info}
}

func TestGoModuleChecksumControllerRecollectsOnlyProofAfterCheckpointWinner(t *testing.T) {
	s, _, _, i := schemaServer(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../store/testdata/go-checksum-timeline-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Module      string                `json:"module"`
		Payload     string                `json:"payload"`
		ModHash     string                `json:"mod_h1"`
		ZIPHashes   map[string]string     `json:"zip_h1"`
		Key         string                `json:"verifier_key"`
		Initial     []byte                `json:"initial_checkpoint"`
		One         []byte                `json:"first_checkpoint"`
		Two         []byte                `json:"second_checkpoint"`
		First       crypt.GoSumDBSnapshot `json:"first"`
		Second      crypt.GoSumDBSnapshot `json:"second"`
		OldAtSecond crypt.GoSumDBSnapshot `json:"old_at_second"`
	}
	if err = json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	c := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
	files := checksumControllerFiles(t, c, log.Payload)
	public := publicGoChecksum{Module: c.Module, Version: c.Version, ZIPHash: log.ZIPHashes[c.Version], ModHash: log.ModHash, Key: log.Key, Initial: log.Initial, Advanced: log.One, Responses: log.First.Responses}
	var winnerLease store.Retrieval
	var winnerResult store.RetrievalResult
	var winOnce sync.Once
	var advanced atomic.Bool
	var mutex sync.Mutex
	calls := map[string]int{}
	winnerErrors := make(chan error, 1)
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		calls[r.URL.Path]++
		mutex.Unlock()
		w.Header().Set("Cache-Control", "max-age=60")
		if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
			wasAdvanced := advanced.Load()
			if strings.HasPrefix(path, "/tile/") {
				winOnce.Do(func() {
					err := s.DB.CompleteRetrieval(ctx, i, winnerLease, winnerResult)
					winnerErrors <- err
					if err == nil {
						advanced.Store(true)
					}
				})
			}
			responses := log.First.Responses
			if wasAdvanced {
				responses = log.OldAtSecond.Responses
			}
			data, ok := responses[path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(data)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
		data, ok := files[kind]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(data)
	}))
	repo := goChecksumCallerRepository(t, s, i, origin.URL, public, false)
	settings, _ := json.Marshal(repo.Settings)
	if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) VALUES($1,'winner','go','proxy','restricted',$2)`, i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	winnerCoordinate := gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}
	winnerFiles := checksumControllerFiles(t, winnerCoordinate, log.Payload)
	inspected, err := gomodule.InspectRepresentations(ctx, bytes.NewReader(winnerFiles["zip"]), int64(len(winnerFiles["zip"])), winnerCoordinate, winnerFiles["mod"], winnerFiles["info"], ziparchive.Limits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64})
	if err != nil || inspected.ZIPHash != log.ZIPHashes[winnerCoordinate.Version] || inspected.GoModHash != log.ModHash {
		t.Fatal("winning checkpoint must bind actual independent bundle", err)
	}
	publication := &store.GoModulePublication{}
	metadata := store.GoModuleMetadata{Profile: store.GoModuleProfile, Module: log.Module, Version: winnerCoordinate.Version, Digests: map[string]string{}}
	for _, kind := range []string{"zip", "mod", "info"} {
		data := winnerFiles[kind]
		object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), crypt.Digest(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		metadata.Digests[kind] = object.Digest
		media := map[string]string{"zip": "application/zip", "mod": "text/plain; charset=utf-8", "info": "application/json"}[kind]
		publication.Objects = append(publication.Objects, store.Artifact{Path: winnerCoordinate.Prefix() + "." + kind, Digest: object.Digest, Size: object.Size, MediaType: media})
		if kind == "zip" {
			winnerResult.Object = &object
		}
	}
	meta, _ := json.Marshal(metadata)
	for n := range publication.Objects {
		publication.Objects[n].Metadata = meta
	}
	snapshot := log.Second
	snapshot.Checkpoint = log.Initial
	proof := store.GoModuleChecksumProof{Profile: store.GoModuleChecksumProfile, Module: log.Module, Version: winnerCoordinate.Version, ZIPHash: inspected.ZIPHash, ModHash: inspected.GoModHash, Snapshot: snapshot}
	proofBytes, _ := json.Marshal(proof)
	proofObject, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(proofBytes), crypt.Digest(proofBytes), int64(len(proofBytes)))
	if err != nil {
		t.Fatal(err)
	}
	publication.Checksum = &store.GoModuleChecksumPublication{Proof: proof, Object: proofObject, ZIPHash: inspected.ZIPHash, ModHash: inspected.GoModHash, ExpectedCheckpointRevision: 0}
	winnerResult.Status = 200
	winnerResult.MediaType = "application/zip"
	winnerResult.Metadata = meta
	winnerResult.FreshSeconds = 60
	winnerResult.StaleSeconds = 60
	winnerResult.GoModule = publication
	winnerLease, err = s.DB.AcquireRetrieval(ctx, i, "winner", winnerCoordinate.Prefix()+".zip", "other-repository-checkpoint-winner", false)
	if err != nil || !winnerLease.Acquired {
		t.Fatal(err)
	}
	resolved, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
	if err != nil || resolved.artifact.Digest == "" || len(resolved.admissions) != 1 || resolved.admissions[0].GoChecksum == nil {
		t.Fatal("one bounded proof recollection did not recover a consistent winner", err)
	}
	select {
	case err := <-winnerErrors:
		if err != nil {
			t.Fatal("owned checkpoint winner failed", err)
		}
	default:
		t.Fatal("test did not advance shared trust during first proof")
	}
	mutex.Lock()
	observed := map[string]int{}
	for path, count := range calls {
		observed[path] = count
	}
	mutex.Unlock()
	for _, kind := range []string{"zip", "mod", "info"} {
		if observed["/go/source/"+c.Prefix()+"."+kind] != 1 {
			t.Fatal("checkpoint recovery re-fetched package bytes", kind)
		}
	}
	lookups := 0
	for path, count := range observed {
		if strings.HasPrefix(path, "/checksum/lookup/") {
			lookups += count
		}
	}
	if lookups != 2 {
		t.Fatal("expected original collection and exactly one proof-only recovery", lookups)
	}
	goCallerCounts(t, s, i, 4)
	checkpoint, err := s.DB.GoModuleChecksumCheckpoint(ctx, i, repo.Name, repo.SourceRevision)
	if err != nil || checkpoint.Revision != 2 || !bytes.Equal(checkpoint.Checkpoint, log.Two) {
		t.Fatal("recovery reset or duplicated winning trust", err)
	}
	if _, err = s.guardResolved(ctx, i, resolved); err != nil {
		t.Fatal("recovered current request proof failed final guard", err)
	}
}

func TestGoModuleChecksumControllerRetainsForkCodeWithoutServingStale(t *testing.T) {
	s, _, _, i := schemaServer(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../store/testdata/go-checksum-timeline-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Module    string                `json:"module"`
		Payload   string                `json:"payload"`
		ModHash   string                `json:"mod_h1"`
		ZIPHashes map[string]string     `json:"zip_h1"`
		Key       string                `json:"verifier_key"`
		Initial   []byte                `json:"initial_checkpoint"`
		One       []byte                `json:"first_checkpoint"`
		First     crypt.GoSumDBSnapshot `json:"first"`
		Fork      crypt.GoSumDBSnapshot `json:"fork"`
	}
	if err = json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	c := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
	files := checksumControllerFiles(t, c, log.Payload)
	public := publicGoChecksum{Module: c.Module, Version: c.Version, ZIPHash: log.ZIPHashes[c.Version], ModHash: log.ModHash, Key: log.Key, Initial: log.Initial, Advanced: log.One, Responses: log.First.Responses}
	var fork atomic.Bool
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
			responses := log.First.Responses
			if fork.Load() {
				responses = log.Fork.Responses
			}
			data, ok := responses[path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(data)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
		data, ok := files[kind]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(data)
	}))
	repo := goChecksumCallerRepository(t, s, i, origin.URL, public, false)
	if _, err = s.resolve(ctx, i, repo, c.Prefix()+".zip", false); err != nil {
		t.Fatal("initial independently verified bytes", err)
	}
	before, err := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", repo.SourceRevision)
	if err != nil || !before.StaleUntil.After(before.Now) {
		t.Fatal("fork fixture must begin with an explicitly retained stale window", err)
	}
	fork.Store(true)
	resolved, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", true)
	if err == nil || resolved.artifact.Digest != "" {
		t.Fatal("signed authority fork served retained bytes")
	}
	after, err := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", repo.SourceRevision)
	if err != nil || after.State != "failed" || after.LastError != "upstream_checksum_fork" || after.StalePermitted() || after.ValidationGeneration != before.ValidationGeneration {
		t.Fatal("known signed fork lost durable classification or granted stale", err)
	}
	checkpoint, err := s.DB.GoModuleChecksumCheckpoint(ctx, i, repo.Name, repo.SourceRevision)
	if err != nil || checkpoint.Revision != 2 || !bytes.Equal(checkpoint.Checkpoint, log.One) {
		t.Fatal("fork changed retained trust", err)
	}
	goCallerCounts(t, s, i, 4)
	if err = s.DB.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var count int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='proxy.retrieval.failed' AND payload::jsonb#>>'{data,failure}'='upstream_checksum_fork'`).Scan(&count)
		if err == nil && count != 1 {
			t.Error("fork failure omitted from common journal/outbox", count)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumControllerCoalescesBundleProofAndReadback(t *testing.T) {
	s, _, token, i := schemaServer(t)
	ctx := context.Background()
	c, files := goOriginBytes(t)
	f := goChecksumPublic(t)
	var mutex sync.Mutex
	calls := map[string]int{}
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		calls[r.URL.Path]++
		mutex.Unlock()
		w.Header().Set("Cache-Control", "max-age=60")
		if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
			data, found := f.Responses[path]
			if !found {
				w.WriteHeader(404)
				return
			}
			w.Write(data)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
		data, ok := files[kind]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(data)
	}))
	repo := goChecksumCallerRepository(t, s, i, origin.URL, f, false)
	start := make(chan struct{})
	var group sync.WaitGroup
	for n := 0; n < 12; n++ {
		kind := []string{"zip", "mod", "info"}[n%3]
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			resolved, err := s.resolve(ctx, i, repo, c.Prefix()+"."+kind, false)
			if err != nil || len(resolved.admissions) != 1 || resolved.admissions[0].GoChecksum == nil {
				t.Error("configured checksum caller did not retain opaque readback", err)
				return
			}
			file, err := s.Blobs.OpenVerified(ctx, i.Tenant, resolved.artifact.Digest, resolved.artifact.Size)
			if err != nil {
				t.Error(err)
				return
			}
			data, err := io.ReadAll(io.LimitReader(file, resolved.artifact.Size+1))
			file.Close()
			if err != nil || !bytes.Equal(data, files[kind]) {
				t.Error("caller lost exact staged representation", err)
				return
			}
			if _, err = s.guardResolved(ctx, i, resolved); err != nil {
				t.Error("final selection lost proof admission", err)
			}
		}()
	}
	close(start)
	group.Wait()
	goCallerCounts(t, s, i, 4)
	mutex.Lock()
	observed := map[string]int{}
	for path, count := range calls {
		observed[path] = count
	}
	mutex.Unlock()
	for _, kind := range []string{"zip", "mod", "info"} {
		if observed["/go/source/"+c.Prefix()+"."+kind] != 1 {
			t.Error("contenders duplicated source representation", kind, observed)
		}
	}
	checksumCalls := 0
	for path, count := range observed {
		if strings.HasPrefix(path, "/checksum/") {
			checksumCalls += count
		}
	}
	if checksumCalls != 2 {
		t.Fatal("one canonical lookup and one authenticated tile expected for the shared fill", checksumCalls)
	}
	checkpoint, err := s.DB.GoModuleChecksumCheckpoint(ctx, i, repo.Name, repo.SourceRevision)
	if err != nil || checkpoint.Revision != 2 || !bytes.Equal(checkpoint.Checkpoint, f.Advanced) {
		t.Fatal("controller did not durably admit signed head", err)
	}
	if w := goHTTP(t, s, token, "GET", "/go/source/"+c.Prefix()+".zip", nil); w.Code != 405 {
		t.Fatal("private controller enabled unqualified public proxy", w.Code)
	}
}

func TestGoModuleChecksumControllerRenewsLeaseWhileProofTransferIsBlocked(t *testing.T) {
	s, _, _, i := schemaServer(t)
	s.ProxyLease = time.Second
	c, files := goOriginBytes(t)
	f := goChecksumPublic(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	var startOnce, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
			if strings.HasPrefix(path, "/lookup/") {
				startOnce.Do(func() { close(started) })
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			data, found := f.Responses[path]
			if !found {
				w.WriteHeader(404)
				return
			}
			w.Write(data)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
		data, ok := files[kind]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(data)
	}))
	repo := goChecksumCallerRepository(t, s, i, origin.URL, f, false)
	done := make(chan error, 1)
	go func() { _, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", false); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("owned checksum transfer did not start")
	}
	original, err := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", repo.SourceRevision)
	if err != nil || original.State != "fetching" {
		t.Fatal("proof transfer lacks a live common lease", err)
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("proof transfer did not renew its lease")
		case <-ticker.C:
		}
		current, err := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", repo.SourceRevision)
		if err != nil {
			t.Fatal(err)
		}
		if current.Generation != original.Generation || current.State != "fetching" {
			t.Fatal("blocked proof lost or replaced the canonical root lease")
		}
		if current.LeaseUntil.After(original.LeaseUntil) {
			break
		}
	}
	if len(s.fillSlots) != 1 {
		t.Fatal("blocked proof did not retain exactly one common fill slot")
	}
	if err = s.DB.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var references, integrity, heads int
		err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.artifacts WHERE repository='source'),(SELECT count(*) FROM cratectl.jobs WHERE queue='integrity'),(SELECT count(*) FROM cratectl.go_checksum_checkpoints)`).Scan(&references, &integrity, &heads)
		if err == nil && (references != 0 || integrity != 0 || heads != 0) {
			t.Error("blocked proof published partial references/work/trust", references, integrity, heads)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("renewed proof fill failed", err)
		}
	case <-ctx.Done():
		t.Fatal("released checksum transfer did not finish")
	}
	goCallerCounts(t, s, i, 4)
}

func TestGoModuleChecksumControllerFailuresNeverPublishPartialTrust(t *testing.T) {
	for _, scenario := range []string{"corrupt-proof", "checksum-mismatch", "authority-unavailable", "origin-absent", "cancelled", "source-changed", "review-required", "integrity-capacity"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			base := context.Background()
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			c, files := goOriginBytes(t)
			f := goChecksumPublic(t)
			if scenario == "checksum-mismatch" {
				var body bytes.Buffer
				z := zip.NewWriter(&body)
				for _, entry := range []struct {
					name string
					data []byte
				}{{"go.mod", files["mod"]}, {"assets/inert.txt", []byte("different owned inert contents\n")}} {
					w, err := z.Create(c.Module + "@" + c.Version + "/" + entry.name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = w.Write(entry.data); err != nil {
						t.Fatal(err)
					}
				}
				if err := z.Close(); err != nil {
					t.Fatal(err)
				}
				files["zip"] = body.Bytes()
			}
			var once sync.Once
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=60")
				if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
					once.Do(func() {
						switch scenario {
						case "cancelled":
							cancel()
						case "source-changed":
							if err := s.DB.Tx(base, i, true, func(tx pgx.Tx) error {
								_, err := tx.Exec(base, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='source'`)
								return err
							}); err != nil {
								t.Error(err)
							}
						case "integrity-capacity":
							if _, err := s.DB.SetQueuePolicy(base, i, "checksum-outbox-capacity", "checksum-outbox-capacity", store.QueuePolicy{Queue: "integrity", Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
								t.Error(err)
							}
						}
					})
					if scenario == "authority-unavailable" {
						w.WriteHeader(503)
						return
					}
					data, found := f.Responses[path]
					if !found {
						w.WriteHeader(404)
						return
					}
					data = bytes.Clone(data)
					if scenario == "corrupt-proof" && strings.HasPrefix(path, "/lookup/") {
						data[len(data)/2] ^= 1
					}
					w.Write(data)
					return
				}
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				if scenario == "origin-absent" && kind == "info" {
					w.WriteHeader(404)
					return
				}
				data, ok := files[kind]
				if !ok {
					w.WriteHeader(404)
					return
				}
				w.Write(data)
			}))
			repo := goChecksumCallerRepository(t, s, i, origin.URL, f, scenario == "review-required")
			resolved, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
			if err == nil || resolved.artifact.Digest != "" {
				t.Fatal("invalid or unapproved checksum caller admitted bytes")
			}
			if scenario == "origin-absent" && !errors.Is(err, store.ErrNotFound) {
				t.Fatal("true initial info absence lost native negative", err)
			}
			if scenario == "review-required" && !errors.Is(err, store.ErrDenied) {
				t.Fatal("checksum evidence bypassed package review", err)
			}
			if scenario == "integrity-capacity" && !errors.Is(err, store.ErrQueueFull) {
				t.Fatal("checksum controller ignored full atomic outbox", err)
			}
			if scenario == "source-changed" && !errors.Is(err, store.ErrSourceChanged) {
				t.Fatal("proof transfer ignored changed source epoch", err)
			}
			if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled proof fill lost context", err)
			}
			wantRefs := 0
			if scenario == "review-required" {
				wantRefs = 4
			}
			goCallerCounts(t, s, i, wantRefs)
			if err = s.DB.Tx(base, i, false, func(tx pgx.Tx) error {
				var heads, history, receipts, ready int
				if err := tx.QueryRow(base, `SELECT (SELECT count(*) FROM cratectl.go_checksum_checkpoints),(SELECT count(*) FROM cratectl.go_checksum_checkpoint_revisions),(SELECT count(*) FROM cratectl.go_module_checksum_receipts),(SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='proxy.retrieval.ready')`).Scan(&heads, &history, &receipts, &ready); err != nil {
					return err
				}
				want := 0
				if scenario == "review-required" {
					want = 1
				}
				if heads != want || history != 2*want || receipts != want || ready != want {
					t.Error("failed fill left partial trust/receipt/ready event", heads, history, receipts, ready)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
