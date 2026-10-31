//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func caseInput(a Artifact, action string, revision int64) HoldCaseRequest {
	return HoldCaseRequest{Path: a.Path, Digest: a.Digest, Action: action, ExpectedRevision: revision, Reason: "Independent owned preservation review"}
}
func caseChange(t *testing.T, db *Store, ctx context.Context, i Identity, repo, id, key string, in HoldCaseRequest) HoldCasePreview {
	t.Helper()
	r, e := db.ChangeHoldCase(ctx, i, repo, id, key, key, in)
	if e != nil {
		t.Fatal(id, in.Action, e)
	}
	var out HoldCasePreview
	if e = json.Unmarshal(r.Body, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestHoldCasesConcurrentIndependentRevisionsAndLegacyProtection(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{"review-a", "review-b"} {
		go func(id string) {
			<-start
			_, e := db.ChangeHoldCase(ctx, i, repo, id, "create-"+id, "create-"+id, caseInput(root, "hold", 0))
			results <- e
		}(id)
	}
	close(start)
	for n := 0; n < 2; n++ {
		if e := <-results; e != nil {
			t.Fatal("independent revision-zero admissions conflicted", e)
		}
	}
	state, e := db.ArtifactState(ctx, i, repo, root.Path)
	if e != nil || !state.Held || !state.CaseHeld || state.LegacyHeld || state.Revision != 2 {
		t.Fatal(state, e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "stale-delete", "stale-delete", lifecycleInput(root, "delete", 0), 100, nil); !errors.Is(e, ErrLifecycleRevision) {
		t.Fatal("case did not fence old lifecycle preview", e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "legacy-hold", "legacy-hold", lifecycleInput(root, "hold", 2), 100, nil); e != nil {
		t.Fatal(e)
	}
	a := caseChange(t, db, ctx, i, repo, "review-a", "release-a", caseInput(root, "release_hold", 1))
	if !a.Current.Held || !a.Current.LegacyHeld || !a.Current.CaseHeld || a.Case.Held || !a.Case.Released || a.Case.HoldReason == "" {
		t.Fatal("release erased other protection or original reason", a)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "legacy-release", "legacy-release", lifecycleInput(root, "release_hold", 4), 100, nil); e != nil {
		t.Fatal(e)
	}
	legacy, _, _, e := db.HoldPage(ctx, i, HoldListRequest{ListRequest: ListRequest{Limit: 10}, State: "released"})
	if e != nil || len(legacy) != 1 || legacy[0].Status != "released" || !legacy[0].Held || legacy[0].LegacyHeld || !legacy[0].CaseHeld {
		t.Fatal("legacy release hid case protection", legacy, e)
	}
	for _, ref := range []string{"latest", "sha256:" + root.Digest} {
		if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", ref, 100); !errors.Is(e, ErrHeld) {
			t.Fatal("case B native protection", ref, e)
		}
	}
	history, _, e := db.HoldCaseHistory(ctx, i, repo, root.Path, "review-a", ListRequest{Limit: 10})
	if e != nil || len(history) != 2 || !history[0].Case.Held || history[1].Case.Held || !history[1].Current.Held {
		t.Fatal("original case receipt snapshots", history, e)
	}
	beforeHash := history[0].EventHash
	last := caseChange(t, db, ctx, i, repo, "review-b", "release-b", caseInput(root, "release_hold", 1))
	if last.Current.Held || last.Current.Revision != 6 {
		t.Fatal(last)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 100); e != nil {
		t.Fatal(e)
	}
	// A hold on an already tombstoned reference protects restore independently.
	caseChange(t, db, ctx, i, repo, "review-a", "reopen-a", caseInput(root, "hold", 2))
	state, e = db.ArtifactState(ctx, i, repo, root.Path)
	if e != nil || !state.Deleted || !state.Held {
		t.Fatal(state, e)
	}
	if _, e = db.RestorationGraph(ctx, i, repo, lifecycleInput(root, "restore", state.Revision)); !errors.Is(e, ErrHeld) {
		t.Fatal("case did not protect restore", e)
	}
	history, _, e = db.HoldCaseHistory(ctx, i, repo, root.Path, "review-a", ListRequest{Limit: 10})
	if e != nil || len(history) != 3 || history[0].EventHash != beforeHash {
		t.Fatal("reopen rewrote original history", e)
	}
}
func TestHoldCasesActualExpiryDoesNotReleaseAnotherCase(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	in := caseInput(root, "hold", 0)
	expiry := time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Second)
	in.HoldUntil = &expiry
	first := caseChange(t, db, ctx, i, repo, "timed", "timed-hold", in)
	if !first.Case.Held {
		t.Fatal(first)
	}
	caseChange(t, db, ctx, i, repo, "ongoing", "ongoing-hold", caseInput(root, "hold", 0))
	time.Sleep(time.Until(expiry) + 20*time.Millisecond)
	rows, _, observed, e := db.HoldCasePage(ctx, i, HoldCaseListRequest{ListRequest: ListRequest{Limit: 10}, State: "expired"})
	if e != nil || len(rows) != 1 || rows[0].CaseID != "timed" || rows[0].Held || rows[0].Released || observed.Before(expiry) {
		t.Fatal(rows, observed, e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 100); !errors.Is(e, ErrHeld) {
		t.Fatal("expiry removed ongoing case", e)
	}
	history, _, e := db.HoldCaseHistory(ctx, i, repo, root.Path, "timed", ListRequest{Limit: 10})
	if e != nil || len(history) != 1 || !history[0].Case.Held || history[0].Action != "hold" {
		t.Fatal("expiry invented or changed receipt", history, e)
	}
	last := caseChange(t, db, ctx, i, repo, "ongoing", "ongoing-release", caseInput(root, "release_hold", 1))
	if last.Current.Held {
		t.Fatal("expired case still enforced", last)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 100); e != nil {
		t.Fatal(e)
	}
}
func TestHoldCasesQueueRollbackReplayAndStaleSameCase(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	before := map[string]int{}
	for _, table := range []string{"events", "jobs", "mutations"} {
		before[table] = retentionCount(t, db, ctx, i, table)
	}
	if e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.queue_policies(tenant,queue,capacity) VALUES($1,'events',1) ON CONFLICT(tenant,queue) DO UPDATE SET capacity=1`, i.Tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	in := caseInput(root, "hold", 0)
	if _, e := db.ChangeHoldCase(ctx, i, repo, "review", "rollback-case", "rollback-case", in); !errors.Is(e, ErrQueueFull) {
		t.Fatal("queue did not reject", e)
	}
	for table, n := range before {
		if got := retentionCount(t, db, ctx, i, table); got != n {
			t.Fatal("partial transaction", table, got, n)
		}
	}
	c, e := db.HoldCase(ctx, i, repo, root.Path, "review")
	if e != nil || c.Revision != 0 {
		t.Fatal(c, e)
	}
	state, e := db.ArtifactState(ctx, i, repo, root.Path)
	if e != nil || state.Revision != 0 || state.Held {
		t.Fatal(state, e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=100000 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	first, e := db.ChangeHoldCase(ctx, i, repo, "review", "rollback-case", "rollback-case", in)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := db.ChangeHoldCase(ctx, i, repo, "review", "rollback-case", "rollback-case", in)
	if e != nil || !replay.Replay || string(replay.Body) != string(first.Body) {
		t.Fatal("lost response replay", e)
	}
	if _, e = db.ChangeHoldCase(ctx, i, repo, "review", "rollback-case", "changed-fingerprint", in); !errors.Is(e, ErrConflict) {
		t.Fatal("substituted request replayed", e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for n := 0; n < 2; n++ {
		go func(n int) {
			<-start
			k := fmt.Sprintf("release-race-%d", n)
			_, e := db.ChangeHoldCase(ctx, i, repo, "review", k, k, caseInput(root, "release_hold", 1))
			results <- e
		}(n)
	}
	close(start)
	success, conflict := 0, 0
	for n := 0; n < 2; n++ {
		e := <-results
		if e == nil {
			success++
		} else if errors.Is(e, ErrLifecycleRevision) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal(success, conflict)
	}
	history, _, e := db.HoldCaseHistory(ctx, i, repo, root.Path, "review", ListRequest{Limit: 10})
	if e != nil || len(history) != 2 {
		t.Fatal("duplicate release event", history, e)
	}
	for _, role := range []string{"writer", "reader", "worker"} {
		other := i
		other.Role = role
		other.CredentialHash = ""
		if _, e = db.ChangeHoldCase(ctx, other, repo, "review", "rollback-case", "rollback-case", in); !errors.Is(e, ErrDenied) {
			t.Fatal("demoted actor replay", role, e)
		}
	}
}
func TestHoldCaseInventoryBoundsStablePaginationAndTenantRLS(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	for n := 0; n < 5; n++ {
		in := caseInput(root, "hold", 0)
		if n == 2 {
			in.Reason = "Review.* literal É"
		}
		id := fmt.Sprintf("case-%d", n)
		caseChange(t, db, ctx, i, repo, id, "place-"+id, in)
	}
	req := HoldCaseListRequest{ListRequest: ListRequest{Limit: 2}, State: "all"}
	first, w, _, e := db.HoldCasePage(ctx, i, req)
	if e != nil || len(first) != 2 || !w.More {
		t.Fatal(first, w, e)
	}
	caseChange(t, db, ctx, i, repo, first[0].CaseID, "release-first", caseInput(root, "release_hold", 1))
	req.Key = w.Last
	second, w2, _, e := db.HoldCasePage(ctx, i, req)
	if e != nil || len(second) != 2 || second[0].CreatedSequence <= first[1].CreatedSequence {
		t.Fatal(second, w2, e)
	}
	req.Key = w2.First
	req.Before = true
	back, _, _, e := db.HoldCasePage(ctx, i, req)
	if e != nil || len(back) != 2 || back[0].CaseID != first[0].CaseID {
		t.Fatal(back, e)
	}
	req.Key = ""
	req.Before = false
	req.Query = "review.*"
	found, _, _, e := db.HoldCasePage(ctx, i, req)
	if e != nil || len(found) != 1 || found[0].CaseID != "case-2" {
		t.Fatal("literal search", found, e)
	}
	in := caseInput(root, "hold", 0)
	in.Reason = strings.Repeat("x", 1024)
	caseChange(t, db, ctx, i, repo, "large", "place-large", in)
	if _, _, _, e = db.HoldCasePage(ctx, i, HoldCaseListRequest{ListRequest: ListRequest{Limit: 10, MetadataBytes: 1024}, CaseID: "large", State: "all"}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized case row silently omitted", e)
	}
	if _, _, e = db.HoldCaseHistory(ctx, i, repo, root.Path, "large", ListRequest{Limit: 10, MetadataBytes: 1024}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized history silently omitted", e)
	}
	other := Identity{Tenant: "other-case-team", Actor: i.Actor, Role: "admin"}
	if rows, _, _, e := db.HoldCasePage(ctx, other, HoldCaseListRequest{ListRequest: ListRequest{Limit: 100}, State: "all"}); e != nil || len(rows) != 0 {
		t.Fatal("RLS inventory leak", e)
	}
	if _, e = db.HoldCase(ctx, other, repo, root.Path, "case-0"); !errors.Is(e, ErrNotFound) {
		t.Fatal("RLS point read leak", e)
	}
	if _, _, e = db.HoldCaseHistory(ctx, other, repo, root.Path, "case-0", ListRequest{Limit: 10}); !errors.Is(e, ErrNotFound) {
		t.Fatal("RLS history leak", e)
	}
	for _, key := range []string{"-1", "0", "1.2", "9223372036854775808"} {
		if (HoldCaseListRequest{ListRequest: ListRequest{Limit: 1, Key: key}}).Validate() == nil {
			t.Fatal("invalid position", key)
		}
	}
	for _, role := range []string{"writer", "reader", "worker"} {
		other := i
		other.Role = role
		if _, _, _, e = db.HoldCasePage(ctx, other, req); !errors.Is(e, ErrDenied) {
			t.Fatal("inventory role leak", e)
		}
	}
	var rls, forced, runtimeSafe bool
	if e = db.Tx(ctx, i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT c.relrowsecurity,c.relforcerowsecurity,NOT r.rolsuper AND NOT r.rolbypassrls AND c.relowner<>r.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN pg_roles r WHERE n.nspname='cratectl' AND c.relname='artifact_hold_cases' AND r.rolname=current_user`).Scan(&rls, &forced, &runtimeSafe)
	}); e != nil || !rls || !forced || !runtimeSafe {
		t.Fatal("hold table/runtime isolation", rls, forced, runtimeSafe, e)
	}
}
func TestHoldCasesRetentionWorkerRechecksRemainingCase(t *testing.T) {
	db, ctx, i, worker, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, i, retentionPolicyInput())
	root := retentionManifest(t, db, ctx, i, "app", "case-retention-late-protection", 3600, nil)
	preview := retentionPreviewFixture(t, db, ctx, i)
	id := retentionAdmit(t, db, ctx, i, preview, "case-retention-admit")
	caseChange(t, db, ctx, i, "retained", "review-a", "retention-case-a", caseInput(root, "hold", 0))
	caseChange(t, db, ctx, i, "retained", "review-b", "retention-case-b", caseInput(root, "hold", 0))
	caseChange(t, db, ctx, i, "retained", "review-a", "retention-release-a", caseInput(root, "release_hold", 1))
	retentionDrain(t, db, ctx, worker, id)
	items, _, e := db.RetentionItems(ctx, i, id, 0, 100)
	if e != nil || len(items) != 1 || items[0].Outcome != "held" {
		t.Fatal("worker ignored case B", items, e)
	}
	state, e := db.ArtifactState(ctx, i, "retained", root.Path)
	if e != nil || state.Deleted || !state.Held {
		t.Fatal(state, e)
	}
	p := retentionPreviewFixture(t, db, ctx, i)
	if p.Eligible != 0 {
		t.Fatal("preview ignored case B", p)
	}
}
