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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleChecksumCapturedForkBlocksSiblingAndSurvivesSaturatedQueues(t *testing.T) {
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
	var calls atomic.Int32
	var fillQueues sync.Once
	queueErrors := make(chan error, 1)
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
			responses := log.First.Responses
			if fork.Load() {
				responses = log.Fork.Responses
				if strings.HasPrefix(path, "/lookup/") {
					fillQueues.Do(func() {
						for _, queue := range []string{"events", "integrity"} {
							if _, err := s.DB.SetQueuePolicy(ctx, i, "fork-"+queue, "fork-"+queue, store.QueuePolicy{Queue: queue, Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
								queueErrors <- err
								return
							}
						}
						queueErrors <- nil
					})
				}
			}
			body, found := responses[path]
			if !found {
				w.WriteHeader(404)
				return
			}
			w.Write(body)
			return
		}
		body, found := files[strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")]
		if !found {
			w.WriteHeader(404)
			return
		}
		w.Write(body)
	}))
	repo := goChecksumCallerRepository(t, s, i, origin.URL, public, false)
	if _, err = s.resolve(ctx, i, repo, c.Prefix()+".zip", false); err != nil {
		t.Fatal(err)
	}
	settings, _ := json.Marshal(repo.Settings)
	if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) VALUES($1,'sibling','go','proxy','restricted',$2)`, i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sibling, err := s.DB.Repository(ctx, i, "sibling")
	if err != nil {
		t.Fatal(err)
	}
	prior, err := s.resolve(ctx, i, sibling, c.Prefix()+".zip", false)
	if err != nil {
		t.Fatal(err)
	}
	object, err := s.Blobs.OpenVerified(ctx, i.Tenant, prior.artifact.Digest, prior.artifact.Size)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, object)
	object.Close()
	if err != nil {
		t.Fatal(err)
	}
	fork.Store(true)
	denied, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", true)
	if !errors.Is(err, store.ErrGoChecksumAuthorityBlocked) || denied.artifact.Digest != "" {
		t.Fatal("signed fork was not durably blocked with full ordinary queues", err)
	}
	select {
	case err := <-queueErrors:
		if err != nil {
			t.Fatal("queue-saturation setup", err)
		}
	default:
		t.Fatal("fixture did not saturate queues during the held proof lookup")
	}
	state, err := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", 0)
	if err != nil || state.State != "failed" || state.LastError != "upstream_checksum_fork" || state.StalePermitted() {
		t.Fatal("fork lost its failed lease classification or granted stale", err)
	}
	original, digest, err := s.DB.GoChecksumFailureEvidence(ctx, i, repo.Name, state.Path, 0, state.Generation)
	if err != nil || digest != crypt.Digest(original) {
		t.Fatal("captured original proof observations were lost", err)
	}
	record, err := store.VerifyGoChecksumFailureEvidence(ctx, original, log.Key)
	if err != nil || record.Classification != "fork" || record.ExpectedCheckpointRevision != 2 || !bytes.Equal(record.Report.Checkpoint, log.One) || !bytes.Equal(record.CurrentCheckpoint, log.One) || len(record.Report.Attempts) == 0 {
		t.Fatal("offline failure verification lost separately retained trust", err)
	}
	for _, a := range record.Report.Attempts {
		if a.Code != "ok" || !bytes.Equal(a.Body, log.Fork.Responses[a.Path]) {
			t.Fatal("original owned authority response was rewritten", a.Code)
		}
	}
	before := calls.Load()
	if _, err := s.guardResolved(ctx, i, prior); !errors.Is(err, store.ErrGoChecksumAuthorityBlocked) {
		t.Fatal("sibling served a package already physically opened before the fork", err)
	}
	if _, err := s.resolve(ctx, i, sibling, c.Prefix()+".mod", false); !errors.Is(err, store.ErrGoChecksumAuthorityBlocked) {
		t.Fatal("blocked sibling used cached bytes", err)
	}
	if _, err := s.resolve(ctx, i, sibling, store.GoModuleCatalogPath(c.Module), true); !errors.Is(err, store.ErrGoChecksumAuthorityBlocked) {
		t.Fatal("blocked key contacted a metadata source", err)
	}
	if calls.Load() != before || len(s.fillSlots) != 0 {
		t.Fatal("blocked key contacted an upstream or leaked a fill slot")
	}
}

func TestGoModuleChecksumUnverifiedObservationPreservesBytesWithoutBlockingRecovery(t *testing.T) {
	s, _, _, i := schemaServer(t)
	ctx := context.Background()
	c, files := goOriginBytes(t)
	public := goChecksumPublic(t)
	var available atomic.Bool
	const failureBody = "owned unverified original response"
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		if path, ok := strings.CutPrefix(r.URL.Path, "/checksum"); ok {
			if !available.Load() {
				w.WriteHeader(503)
				w.Write([]byte(failureBody))
				return
			}
			if data, found := public.Responses[path]; found {
				w.Write(data)
				return
			}
			w.WriteHeader(404)
			return
		}
		if data, found := files[strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")]; found {
			w.Write(data)
			return
		}
		w.WriteHeader(404)
	}))
	repo := goChecksumCallerRepository(t, s, i, origin.URL, public, false)
	failed, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", false)
	if err == nil || failed.artifact.Digest != "" {
		t.Fatal("unavailable checksum authority approved bytes")
	}
	lease, err := s.DB.Retrieval(ctx, i, repo.Name, c.Prefix()+".zip", 0)
	if err != nil || lease.LastError != "upstream_checksum_unverified" || lease.StalePermitted() {
		t.Fatal("unverified observation became a fork or stale admission", err)
	}
	raw, _, err := s.DB.GoChecksumFailureEvidence(ctx, i, repo.Name, lease.Path, 0, lease.Generation)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.VerifyGoChecksumFailureEvidence(ctx, raw, public.Key)
	if err != nil || record.Classification != "unverified" || len(record.Report.Attempts) != 1 || record.Report.Attempts[0].Status != 503 || string(record.Report.Attempts[0].Body) != failureBody {
		t.Fatal("unverified original response was lost or authenticated as a fork", err)
	}
	state, err := s.DB.GoChecksumState(ctx, i, repo.Name, 0)
	if err != nil || state.Blocked || state.Checkpoint.Revision != 0 {
		t.Fatal("unknown evidence changed trust or froze a key", err)
	}
	goCallerCounts(t, s, i, 0)
	available.Store(true)
	recovered, err := s.resolve(ctx, i, repo, c.Prefix()+".zip", true)
	if err != nil || recovered.artifact.Digest == "" {
		t.Fatal("actual verified recovery after unverified observation failed", err)
	}
	if _, err = s.guardResolved(ctx, i, recovered); err != nil {
		t.Fatal(err)
	}
	if state, err := s.DB.GoChecksumState(ctx, i, repo.Name, 0); err != nil || state.Blocked || state.Checkpoint.Revision != 2 {
		t.Fatal("verified recovery did not advance its own retained timeline", err)
	}
	retained, _, err := s.DB.GoChecksumFailureEvidence(ctx, i, repo.Name, lease.Path, 0, lease.Generation)
	if err != nil || !bytes.Equal(retained, raw) {
		t.Fatal("successful recovery rewrote original failure evidence", err)
	}
	goCallerCounts(t, s, i, 4)
}
