//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func jobFixture(t *testing.T) (*Store, context.Context, Identity, WorkerIdentity, string, string) {
	t.Helper()
	ctx := context.Background()
	db, e := Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Pool.Close)
	tenant := fmt.Sprintf("jobs-%d", time.Now().UnixNano())
	adminToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	workerToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []struct{ actor, role, token string }{{"operator", "admin", adminToken}, {"executor", "worker", workerToken}} {
		if e = Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), tenant, p.actor, p.role, p.token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	admin, e := db.Authenticate(ctx, adminToken)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := db.AuthenticateWorker(ctx, workerToken)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Authenticate(ctx, workerToken); e == nil {
		t.Fatal("worker credential authenticated to public API")
	}
	if _, e = db.AuthenticateWorker(ctx, adminToken); e == nil {
		t.Fatal("public admin credential entered worker purpose")
	}
	if _, e = db.Mutate(ctx, admin, "", "", "repository.created", func(tx pgx.Tx) (any, int, error) {
		r := Repository{Name: "packages", Format: "generic"}
		return r, 201, CreateRepository(ctx, tx, admin, r)
	}); e != nil {
		t.Fatal(e)
	}
	return db, ctx, admin, worker, workerToken, adminToken
}
func jobPolicy(t *testing.T, db *Store, ctx context.Context, i Identity, capacity, running, attempts int) {
	t.Helper()
	_, e := db.SetQueuePolicy(ctx, i, "", "", QueuePolicy{Queue: "integrity", Capacity: capacity, MaxRunning: running, MaxAttempts: attempts, RetrySeconds: 1, RetryMaxSeconds: 4})
	if e != nil {
		t.Fatal(e)
	}
}
func TestDurableJobsPublicationFencesCancellationAndCapacity(t *testing.T) {
	db, ctx, admin, worker, workerToken, _ := jobFixture(t)
	jobPolicy(t, db, ctx, admin, 10, 1, 2)
	a := Artifact{Path: "original", Digest: strings.Repeat("a", 64), Size: 10, MediaType: "application/octet-stream"}
	alias := a
	alias.Path = "alias"
	if e := db.Publish(ctx, admin, "packages", []Artifact{a, alias}); e != nil {
		t.Fatal(e)
	}
	jobs, _, e := db.Jobs(ctx, admin, "integrity", "", "", 100)
	if e != nil || len(jobs) != 1 {
		t.Fatalf("publication did not atomically deduplicate exact byte work: %d %v", len(jobs), e)
	}
	j, e := db.ClaimJob(ctx, worker, "integrity", "node-a", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(j)
	if strings.Contains(string(raw), j.Token) || j.Token == "" {
		t.Fatal("claim fence leaked or was absent")
	}
	if _, e = db.ClaimJob(ctx, worker, "integrity", "node-b", time.Second); !errors.Is(e, ErrBusy) {
		t.Fatal("persisted running cap was bypassed", e)
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET lease_until='epoch' WHERE sequence=$1 AND task=$2`, j.Sequence, j.Task)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	newer, e := db.ClaimJob(ctx, worker, "integrity", "node-b", time.Second)
	if e != nil || newer.Generation <= j.Generation || newer.Token == j.Token {
		t.Fatal("expired claim did not advance fence", e)
	}
	if _, e = db.FinishIntegrity(ctx, worker, j, "verified"); !errors.Is(e, ErrJobLeaseLost) {
		t.Fatal("stale worker committed an observation", e)
	}
	if e = db.RenewJob(ctx, worker, j, time.Second); !errors.Is(e, ErrJobLeaseLost) {
		t.Fatal("stale heartbeat resurrected a claim", e)
	}
	if state, e := db.FailJob(ctx, worker, newer, "handler_failure", false); e != nil || state != "failed" {
		t.Fatal("attempt cap did not terminate retry", state, e)
	}
	result, e := db.ControlJob(ctx, admin, "retry-operation", "same", j.ID(), "retry", false)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := db.ControlJob(ctx, admin, "retry-operation", "same", j.ID(), "retry", false)
	if e != nil || !replay.Replay || string(result.Body) != string(replay.Body) {
		t.Fatal("job retry was not idempotent", e)
	}
	current, e := db.ClaimJob(ctx, worker, "integrity", "node-c", time.Second)
	if e != nil || current.Attempts != 3 || current.CycleAttempts != 1 {
		t.Fatal("operator retry lost attempt history", e)
	}
	if _, e = db.ControlJob(ctx, admin, "cancel-operation", "same", current.ID(), "cancel", false); e != nil {
		t.Fatal(e)
	}
	if e = db.RenewJob(ctx, worker, current, time.Second); !errors.Is(e, ErrJobCancelled) {
		t.Fatal("heartbeat ignored cancellation", e)
	}
	if state, e := db.FinishIntegrity(ctx, worker, current, "verified"); e != nil || state != "cancelled" {
		t.Fatal("cancellation fabricated success", state, e)
	}
	observations, _, e := db.JobObservations(ctx, admin, j.ID(), 0, 100)
	if e != nil || len(observations) != 0 {
		t.Fatal("stale/cancelled attempt produced integrity evidence", e)
	}
	jobPolicy(t, db, ctx, admin, 1, 1, 2)
	next := a
	next.Path = "next"
	next.Digest = strings.Repeat("b", 64)
	if e = db.Publish(ctx, admin, "packages", []Artifact{next}); e != nil {
		t.Fatal(e)
	}
	blocked := a
	blocked.Path = "blocked"
	blocked.Digest = strings.Repeat("c", 64)
	var before, after int64
	if e = db.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT max(sequence) FROM cratectl.events`).Scan(&before)
	}); e != nil {
		t.Fatal(e)
	}
	if e = db.Publish(ctx, admin, "packages", []Artifact{blocked}); !errors.Is(e, ErrQueueFull) {
		t.Fatal("queue saturation accepted publication", e)
	}
	if _, e = db.Artifact(ctx, admin, "packages", "blocked"); !errors.Is(e, ErrNotFound) {
		t.Fatal("saturation left a visible artifact", e)
	}
	if e = db.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT max(sequence) FROM cratectl.events`).Scan(&after)
	}); e != nil || before != after {
		t.Fatal("saturation left a journal effect", e)
	}
	// A saturated queue cannot block owner recovery or credential revocation.
	jobPolicy(t, db, ctx, admin, 20, 1, 2)
	countBefore, _, e := db.Jobs(ctx, admin, "events", "", "", 1000)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 100; n++ {
		event, e := db.ClaimJob(ctx, worker, "events", "projector", time.Second)
		if errors.Is(e, ErrNotFound) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		p, e := db.JobEvent(ctx, worker, event, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		if state, e := db.FinishEvent(ctx, worker, event, p); e != nil || state != "succeeded" {
			t.Fatal(state, e)
		}
	}
	countAfter, _, e := db.Jobs(ctx, admin, "events", "", "", 1000)
	if e != nil || len(countBefore) != len(countAfter) {
		t.Fatal("job lifecycle recursively produced outbox work", e)
	}
	activity, _, e := db.Activity(ctx, admin, 0, 1000)
	if e != nil || len(activity) != len(countBefore) {
		t.Fatal("source events were not actually indexed", e)
	}
	if e = Revoke(ctx, os.Getenv("CRATECTL_OWNER_DSN"), workerToken); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ClaimJob(ctx, worker, "integrity", "revoked", time.Second); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("revoked worker retained execution authority", e)
	}
}
func TestDurableJobsConcurrentClaimsRLSAndExpiredCancellation(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	jobPolicy(t, db, ctx, admin, 10, 2, 3)
	artifacts := []Artifact{}
	for n := 0; n < 4; n++ {
		artifacts = append(artifacts, Artifact{Path: fmt.Sprintf("object-%d", n), Digest: crypt.Digest([]byte{byte(n)}), Size: 1, MediaType: "application/octet-stream"})
	}
	if e := db.Publish(ctx, admin, "packages", artifacts); e != nil {
		t.Fatal(e)
	}
	var lock sync.Mutex
	claimed := []Job{}
	var all sync.WaitGroup
	for n := 0; n < 8; n++ {
		all.Add(1)
		go func(n int) {
			defer all.Done()
			j, e := db.ClaimJob(ctx, worker, "integrity", fmt.Sprintf("node-%d", n), 10*time.Second)
			if e == nil {
				lock.Lock()
				claimed = append(claimed, j)
				lock.Unlock()
			} else if !errors.Is(e, ErrBusy) {
				t.Error(e)
			}
		}(n)
	}
	all.Wait()
	if len(claimed) != 2 || claimed[0].ID() == claimed[1].ID() {
		t.Fatal("distributed tenant lane capacity/claim uniqueness failed", len(claimed))
	}
	forged := worker
	forged.Tenant = "other-tenant"
	if _, e := db.WorkerJob(ctx, forged, claimed[0].Sequence, claimed[0].Task); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("worker identity crossed tenant scope", e)
	}
	for _, table := range []string{"jobs", "queue_policies", "event_projections", "integrity_observations"} {
		var n int
		if e := db.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&n); e != nil || n != 0 {
			t.Fatal("unscoped worker state leaked", table, n, e)
		}
	}
	// Reap an expired cancellation even if no runnable work follows it.
	for _, j := range claimed {
		if _, e := db.ControlJob(ctx, admin, "", "", j.ID(), "cancel", false); e != nil {
			t.Fatal(e)
		}
	}
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET state=CASE WHEN state='pending' THEN 'cancel_requested' ELSE state END,lease_until='epoch' WHERE queue='integrity'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ClaimJob(ctx, worker, "integrity", "reaper", time.Second); !errors.Is(e, ErrNotFound) {
		t.Fatal("cancelled queue unexpectedly produced work", e)
	}
	rows, _, e := db.Jobs(ctx, admin, "integrity", "cancelled", "", 100)
	if e != nil || len(rows) != 4 {
		t.Fatal("empty claim rolled back cancellation recovery", len(rows), e)
	}
}

func TestWorkerActivityDoesNotLoseLateProjection(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	if e := db.Publish(ctx, admin, "packages", []Artifact{{Path: "ordered", Digest: strings.Repeat("a", 64), Size: 1, MediaType: "application/octet-stream"}}); e != nil {
		t.Fatal(e)
	}
	first, e := db.ClaimJob(ctx, worker, "events", "slow", 10*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	second, e := db.ClaimJob(ctx, worker, "events", "fast", 10*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	b, e := db.JobEvent(ctx, worker, second, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.FinishEvent(ctx, worker, second, b); e != nil {
		t.Fatal(e)
	}
	page, _, e := db.Activity(ctx, admin, 0, 1)
	if e != nil || len(page) != 1 {
		t.Fatal(e)
	}
	cursor := page[0].Position
	a, e := db.JobEvent(ctx, worker, first, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.FinishEvent(ctx, worker, first, a); e != nil {
		t.Fatal(e)
	}
	late, _, e := db.Activity(ctx, admin, cursor, 1)
	if e != nil || len(late) != 1 || late[0].Sequence != first.Sequence {
		t.Fatal("activity cursor lost an older source event completed later", len(late), e)
	}
}

func TestWorkerExpiryIsRecheckedAfterTenantLockWait(t *testing.T) {
	db, ctx, admin, _, _, _ := jobFixture(t)
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	expires := time.Now().Add(time.Second)
	if e = Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), admin.Tenant, "short-lived", "worker", token, expires); e != nil {
		t.Fatal(e)
	}
	expiring, e := db.AuthenticateWorker(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	holder := make(chan error, 1)
	go func() { holder <- db.Tx(ctx, admin, true, func(pgx.Tx) error { close(held); <-release; return nil }) }()
	<-held
	outcome := make(chan error, 1)
	go func() { _, e := db.ClaimJob(ctx, expiring, "events", "expired", time.Second); outcome <- e }()
	blocked := false
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		var n int
		if e = db.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename=current_user AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock%' AND xact_start<$1`, expires).Scan(&n); e != nil {
			close(release)
			t.Fatal(e)
		}
		if n > 0 {
			blocked = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked {
		close(release)
		<-holder
		t.Fatal("worker transaction was not confirmed waiting before expiry")
	}
	if delay := time.Until(expires.Add(30 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	close(release)
	if e = <-holder; e != nil {
		t.Fatal(e)
	}
	if e = <-outcome; !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("worker used transaction-start time to outlive credential expiry", e)
	}
}

func TestQueueSaturationDoesNotStrandProxyLease(t *testing.T) {
	db, ctx, admin, _, _, _ := jobFixture(t)
	cfg := Repository{Name: "upstream", Format: "generic", Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "https://registry.example/", Networks: []string{"0.0.0.0/0"}}}}
	if _, e := db.Mutate(ctx, admin, "", "", "repository.created", func(tx pgx.Tx) (any, int, error) { return cfg, 201, CreateRepository(ctx, tx, admin, cfg) }); e != nil {
		t.Fatal(e)
	}
	lease, e := db.AcquireRetrieval(ctx, admin, cfg.Name, "object", "source-worker", false)
	if e != nil {
		t.Fatal(e)
	}
	events, _, e := db.Jobs(ctx, admin, "events", "", "", 100)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.SetQueuePolicy(ctx, admin, "", "", QueuePolicy{Queue: "events", Capacity: len(events), MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); e != nil {
		t.Fatal(e)
	}
	result := RetrievalResult{Status: 200, FreshSeconds: 60, Object: &blob.Object{Digest: strings.Repeat("e", 64), Size: 1}}
	if e = db.CompleteRetrieval(ctx, admin, lease, result); !errors.Is(e, ErrQueueFull) {
		t.Fatal("saturated source completion was admitted", e)
	}
	state, e := db.Retrieval(ctx, admin, cfg.Name, "object")
	if e != nil || state.State != "failed" || state.LastError != "queue_capacity" {
		t.Fatal("queue rejection stranded an owned fetching lease", state.State, e)
	}
	if _, e = db.Artifact(ctx, admin, cfg.Name, "object"); !errors.Is(e, ErrNotFound) {
		t.Fatal("queue rejection partially published bytes", e)
	}
	if _, e = db.SetQueuePolicy(ctx, admin, "", "", QueuePolicy{Queue: "events", Capacity: 100, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); e != nil {
		t.Fatal(e)
	}
	replacement, e := db.AcquireRetrieval(ctx, admin, cfg.Name, "object", "recovered-worker", false)
	if e != nil || !replacement.Acquired || replacement.Generation <= lease.Generation {
		t.Fatal("capacity repair did not permit immediate fenced retrieval", e)
	}
	if e = db.CompleteRetrieval(ctx, admin, lease, result); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("abandoned owner reused old fence", e)
	}
}
