//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestHoldInventoryPagesHistoryAndIsolation(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	for n := 0; n < 5; n++ {
		a := root
		a.Digest = strings.Repeat(fmt.Sprintf("%x", n+3), 64)
		a.MediaType = integrationOCIIndex
		a.Path = "app/manifests/sha256:" + a.Digest
		if e := publishOCIFixture(db, ctx, i, repo, a, OCIManifestMetadata{Validated: true, References: []string{}, Descriptors: map[string]OCIDescriptor{}}); e != nil {
			t.Fatal(e)
		}
		in := lifecycleInput(a, "hold", 0)
		if n == 2 {
			in.Reason = "Review.* literal É"
		}
		if _, e := db.ChangeArtifactState(ctx, i, repo, fmt.Sprintf("place-%d", n), fmt.Sprintf("place-fp-%d", n), in, 100, nil); e != nil {
			t.Fatal(e)
		}
	}
	req := HoldListRequest{ListRequest: ListRequest{Limit: 2}, State: "all"}
	first, w, observed, e := db.HoldPage(ctx, i, req)
	if e != nil || len(first) != 2 || !w.More || observed.IsZero() {
		t.Fatal("first page", len(first), w, e)
	}
	req.Key = w.Last
	second, w2, _, e := db.HoldPage(ctx, i, req)
	if e != nil || len(second) != 2 || !w2.More || second[0].Path <= first[1].Path {
		t.Fatal("forward page", w2, e)
	}
	req.Key = w2.First
	req.Before = true
	previous, _, _, e := db.HoldPage(ctx, i, req)
	if e != nil || len(previous) != 2 || previous[0].Path != first[0].Path || previous[1].Path != first[1].Path {
		t.Fatal("reverse page", previous, e)
	}
	req.Key = ""
	req.Before = false
	req.Query = "review.*"
	found, _, _, e := db.HoldPage(ctx, i, req)
	if e != nil || len(found) != 1 || found[0].HoldReason != "Review.* literal É" {
		t.Fatal("literal folded search", found, e)
	}
	target := first[0].ArtifactState
	release := ArtifactStateRequest{Action: "release_hold", Path: target.Path, Digest: target.Digest, ExpectedRevision: target.Revision, Reason: "Review complete"}
	result, e := db.ChangeArtifactState(ctx, i, repo, "release-once", "release-once-fp", release, 100, nil)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := db.ChangeArtifactState(ctx, i, repo, "release-once", "release-once-fp", release, 100, nil)
	if e != nil || !replay.Replay || string(replay.Body) != string(result.Body) {
		t.Fatal("release replay", e)
	}
	history, hw, e := db.HoldHistory(ctx, i, repo, target.Path, ListRequest{Limit: 1})
	if e != nil || len(history) != 1 || !hw.More || history[0].Action != "hold" || !history[0].State.Held {
		t.Fatal("first immutable receipt", history, e)
	}
	later, lw, e := db.HoldHistory(ctx, i, repo, target.Path, ListRequest{Limit: 1, Key: hw.Last})
	if e != nil || len(later) != 1 || later[0].Action != "release_hold" || later[0].State.Held || later[0].Sequence <= history[0].Sequence || lw.More {
		t.Fatal("release receipt", later, e)
	}
	earlier, _, e := db.HoldHistory(ctx, i, repo, target.Path, ListRequest{Limit: 1, Key: lw.First, Before: true})
	if e != nil || len(earlier) != 1 || earlier[0].EventHash != history[0].EventHash {
		t.Fatal("reverse receipt", e)
	}
	released, _, _, e := db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 100}, State: "released"})
	if e != nil || len(released) != 1 || released[0].Path != target.Path {
		t.Fatal("released discovery", released, e)
	}
	// A native tombstone without a hold receipt must not appear as released.
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 100); e != nil {
		t.Fatal(e)
	}
	released, _, _, e = db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 100}, State: "released"})
	if e != nil || len(released) != 1 {
		t.Fatal("never-held deletion mislabeled", released, e)
	}
	for _, role := range []string{"writer", "reader", "worker"} {
		other := i
		other.Role = role
		if _, _, _, e = db.HoldPage(ctx, other, req); !errors.Is(e, ErrDenied) {
			t.Fatal("non-admin inventory", role, e)
		}
		if _, _, e = db.HoldHistory(ctx, other, repo, target.Path, ListRequest{Limit: 1}); !errors.Is(e, ErrDenied) {
			t.Fatal("non-admin history", role, e)
		}
	}
	other := Identity{Tenant: "other-hold-tenant", Actor: i.Actor, Role: "admin"}
	if values, _, _, err := db.HoldPage(ctx, other, HoldListRequest{ListRequest: ListRequest{Limit: 100}, State: "all"}); err != nil || len(values) != 0 {
		t.Fatal("RLS inventory leak", err)
	}
	if _, _, err := db.HoldHistory(ctx, other, repo, target.Path, ListRequest{Limit: 100}); !errors.Is(err, ErrNotFound) {
		t.Fatal("RLS history leak", err)
	}
	e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE cratectl.events SET payload=payload WHERE false")
		return err
	})
	var pe *pgconn.PgError
	if !errors.As(e, &pe) || pe.Code != "42501" {
		t.Fatal("runtime can rewrite immutable history", e)
	}
}

func TestHoldActualExpiryKeepsOriginalReceipt(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(3 * time.Second)
	in := lifecycleInput(root, "hold", 0)
	in.HoldUntil = &expires
	result, e := db.ChangeArtifactState(ctx, i, repo, "timed-hold", "timed-hold-fp", in, 100, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 100); !errors.Is(e, ErrHeld) {
		t.Fatal("live timed hold not enforced", e)
	}
	initial, _, _, e := db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 10}, State: "active"})
	if e != nil || len(initial) != 1 {
		t.Fatal("active expiry observation", e)
	}
	// Real elapsed time, without editing hold clocks or durable rows.
	time.Sleep(time.Until(expires) + 20*time.Millisecond)
	expired, _, at, e := db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 10}, State: "expired"})
	if e != nil || len(expired) != 1 || expired[0].Held || expired[0].Status != "expired" || at.Before(expires) {
		t.Fatal("expired observation", expired, at, e)
	}
	history, _, e := db.HoldHistory(ctx, i, repo, root.Path, ListRequest{Limit: 10})
	if e != nil || len(history) != 1 || !history[0].State.Held || history[0].State.HoldUntil == nil || !history[0].State.HoldUntil.Equal(expires) {
		t.Fatal("expiry rewrote original receipt", history, e)
	}
	replay, e := db.ChangeArtifactState(ctx, i, repo, "timed-hold", "timed-hold-fp", in, 100, nil)
	if e != nil || !replay.Replay || string(replay.Body) != string(result.Body) {
		t.Fatal("expired admission replay lost original response", e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 100); e != nil {
		t.Fatal("expired hold still blocks native deletion", e)
	}
}

func TestHoldMutationRollbackAndConcurrentRevision(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	if e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO cratectl.queue_policies(tenant,queue,capacity) VALUES($1,'events',1) ON CONFLICT(tenant,queue) DO UPDATE SET capacity=1", i.Tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	hold := lifecycleInput(root, "hold", 0)
	if _, e := db.ChangeArtifactState(ctx, i, repo, "rollback-hold", "rollback-hold-fp", hold, 100, nil); !errors.Is(e, ErrQueueFull) {
		t.Fatal("queue admission did not fail", e)
	}
	state, e := db.ArtifactState(ctx, i, repo, root.Path)
	if e != nil || state.Revision != 0 || state.Held {
		t.Fatal("failed hold changed durable state", state, e)
	}
	history, _, e := db.HoldHistory(ctx, i, repo, root.Path, ListRequest{Limit: 100})
	if e != nil || len(history) != 0 {
		t.Fatal("failed hold left a history receipt", e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE cratectl.queue_policies SET capacity=100000 WHERE queue='events'")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "rollback-hold", "rollback-hold-fp", hold, 100, nil); e != nil {
		t.Fatal("retry after queue recovery", e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for n := 0; n < 2; n++ {
		go func(n int) {
			<-start
			in := lifecycleInput(root, "release_hold", 1)
			in.Reason = fmt.Sprintf("administrator %d", n)
			_, err := db.ChangeArtifactState(ctx, i, repo, fmt.Sprintf("release-race-%d", n), fmt.Sprintf("release-race-fp-%d", n), in, 100, nil)
			results <- err
		}(n)
	}
	close(start)
	success, conflict := 0, 0
	for n := 0; n < 2; n++ {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, ErrLifecycleRevision) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("stale release was not fenced", success, conflict)
	}
	history, _, e = db.HoldHistory(ctx, i, repo, root.Path, ListRequest{Limit: 100})
	if e != nil || len(history) != 2 {
		t.Fatal("concurrent release receipt duplicated", e)
	}
}

func TestHoldPageBudgetAndMaximumPosition(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	in := lifecycleInput(root, "hold", 0)
	in.Reason = strings.Repeat("x", 1024)
	if _, e := db.ChangeArtifactState(ctx, i, repo, "bounded-hold", "bounded-hold-fp", in, 100, nil); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 10, MetadataBytes: 1024}, State: "all"}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized first row was silently omitted", e)
	}
	if _, _, e := db.HoldHistory(ctx, i, repo, root.Path, ListRequest{Limit: 10, MetadataBytes: 1024}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized history snapshot silently omitted", e)
	}
	for _, req := range []HoldListRequest{{ListRequest: ListRequest{Limit: 101}}, {ListRequest: ListRequest{Limit: 1}, State: "invalid"}, {ListRequest: ListRequest{Limit: 1, Key: "not-a-position"}}, {ListRequest: ListRequest{Limit: 1, Query: "bad\nquery"}}} {
		if req.Validate() == nil {
			t.Fatal("invalid input accepted", req.State)
		}
	}
	req := HoldListRequest{ListRequest: ListRequest{Limit: 1, Key: strings.Repeat("r", 63) + "\n" + strings.Repeat("a", 1966) + "/manifests/sha256:" + strings.Repeat("1", 64)}}
	if len(req.Key) != 2112 || req.Validate() != nil {
		t.Fatal("maximum canonical global key rejected", len(req.Key))
	}
	if (ListRequest{Limit: 1, Key: req.Key}).Validate() == nil {
		t.Fatal("legacy endpoint key limit expanded")
	}
}
