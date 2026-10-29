//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func createTestUpload(t *testing.T, db *Store, ctx context.Context, i Identity, repo string) string {
	t.Helper()
	id, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.MutateRepository(ctx, i, repo, "", "", "oci.upload.created", func(tx pgx.Tx) (any, int, error) {
		return map[string]string{"upload_id": id}, 202, CreateUpload(ctx, tx, i, repo, "app", id, 32, time.Hour)
	})
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func claimTestUpload(t *testing.T, db *Store, ctx context.Context, i Identity, repo, id string) Upload {
	t.Helper()
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	u, e := db.ClaimUpload(ctx, i, repo, "app", id, token, -1, time.Minute, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	return u
}
func acceptTestUpload(db *Store, ctx context.Context, i Identity, u Upload, p UploadPart) error {
	_, e := db.MutateRepository(ctx, i, u.Repository, "", "", "oci.upload.progress", func(tx pgx.Tx) (any, int, error) {
		offset, e := AcceptUpload(ctx, tx, i, u, UploadPart{}, p, nil, 4, time.Hour)
		return map[string]any{"offset": offset}, 202, e
	})
	return e
}
func TestUploadsFenceOffsetsPartsAuthorizationAndCancellation(t *testing.T) {
	db, ctx, admin, _, _, _ := jobFixture(t)
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, admin, Repository{Name: "images", Format: "oci"})
	}); e != nil {
		t.Fatal(e)
	}
	id := createTestUpload(t, db, ctx, admin, "images")
	first := claimTestUpload(t, db, ctx, admin, "images", id)
	token, _ := crypt.Token()
	if _, e := db.ClaimUpload(ctx, admin, "images", "app", id, token, 0, time.Minute, time.Hour); !errors.Is(e, ErrUploadBusy) {
		t.Fatal("overlapping owner", e)
	}
	if e := acceptTestUpload(db, ctx, admin, first, UploadPart{Digest: strings.Repeat("a", 64), Size: 5, Offset: 1}); !errors.Is(e, ErrConflict) {
		t.Fatal("offset accepted", e)
	}
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET operation_until='epoch' WHERE id=$1`, id)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := db.RenewUpload(ctx, admin, first, time.Minute, time.Hour); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("expired owner resurrected", e)
	}
	second := claimTestUpload(t, db, ctx, admin, "images", id)
	if second.Generation <= first.Generation {
		t.Fatal("generation did not advance")
	}
	if e := acceptTestUpload(db, ctx, admin, first, UploadPart{Digest: strings.Repeat("a", 64), Size: 5}); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("stale owner committed", e)
	}
	if e := db.ReleaseUpload(ctx, admin, first); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("stale cleanup released new owner", e)
	}
	p := UploadPart{Digest: strings.Repeat("b", 64), Size: 5}
	if e := acceptTestUpload(db, ctx, admin, second, p); e != nil {
		t.Fatal(e)
	}
	current, e := db.Upload(ctx, admin, "images", "app", id)
	if e != nil || current.Offset != 5 {
		t.Fatal(current, e)
	}
	third := claimTestUpload(t, db, ctx, admin, "images", id)
	parts, e := db.UploadParts(ctx, admin, third, 4, 512)
	if e != nil || len(parts) != 1 || parts[0].Digest != p.Digest {
		t.Fatal(parts, e)
	}
	if _, e = db.UploadParts(ctx, admin, third, 4, 127); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("metadata limit bypass", e)
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, e = db.Upload(ctx, other, "images", "app", id); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant crossed", e)
	}
	if e = db.CancelUpload(ctx, admin, "images", "app", id); e != nil {
		t.Fatal(e)
	}
	if e = acceptTestUpload(db, ctx, admin, third, UploadPart{Digest: strings.Repeat("c", 64), Size: 4, Offset: 5}); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("cancelled upload accepted", e)
	}
	if e = db.RenewUpload(ctx, admin, third, time.Minute, time.Hour); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("cancelled upload renewed", e)
	}
}

func reconciliationID(t *testing.T, r Result) string {
	t.Helper()
	var data struct{ Job string }
	if e := json.Unmarshal(r.Body, &data); e != nil || data.Job == "" {
		t.Fatal(string(r.Body), e)
	}
	return data.Job
}
func TestReconciliationIsResumableBoundedFencedAndPreservesLiveWork(t *testing.T) {
	db, ctx, admin, worker, _, _ := jobFixture(t)
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if e := CreateRepository(ctx, tx, admin, Repository{Name: "images", Format: "oci"}); e != nil {
			return e
		}
		return CreateRepository(ctx, tx, admin, Repository{Name: "source", Format: "generic", Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:39876/", Networks: []string{"127.0.0.1/32"}}, Cache: CacheSettings{FreshSeconds: 60}}})
	}); e != nil {
		t.Fatal(e)
	}
	dead, e := db.AcquireRetrievalWithLease(ctx, admin, "source", "dead", "first", false, 32, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	live, e := db.AcquireRetrievalWithLease(ctx, admin, "source", "live", "live", false, 32, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	late, e := db.AcquireRetrievalWithLease(ctx, admin, "source", "late", "late", false, 32, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	expired := createTestUpload(t, db, ctx, admin, "images")
	abandoned := createTestUpload(t, db, ctx, admin, "images")
	active := createTestUpload(t, db, ctx, admin, "images")
	old := claimTestUpload(t, db, ctx, admin, "images", abandoned)
	current := claimTestUpload(t, db, ctx, admin, "images", active)
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE path='dead'`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET expires_at='epoch' WHERE id=$1`, expired); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET operation_until='epoch' WHERE id=$1`, abandoned)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	preview, e := db.PreviewReconciliation(ctx, admin, ReconciliationRequest{PageSize: 1})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(preview)
	if strings.Contains(string(raw), old.Token) || !strings.Contains(string(raw), "bytes_deleted") {
		t.Fatal("preview leak", string(raw))
	}
	request := ReconciliationRequest{PageSize: 1}
	first, e := db.StartReconciliation(ctx, admin, "recover-one", "same", request)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := db.StartReconciliation(ctx, admin, "recover-one", "same", request)
	if e != nil || !replay.Replay || string(first.Body) != string(replay.Body) {
		t.Fatal("request replay", e)
	}
	id := reconciliationID(t, first)
	// This lease expires after the run's cutoff; it belongs to a later run.
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until=clock_timestamp() WHERE path='late'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	j, e := db.ClaimJob(ctx, worker, "maintenance", "node-a", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if state, e := db.ReconcileLeases(ctx, worker, j); e != nil || state != "pending" {
		t.Fatal("first page", state, e)
	}
	if _, e = db.ReconcileLeases(ctx, worker, j); !errors.Is(e, ErrJobLeaseLost) {
		t.Fatal("stale checkpoint repeated", e)
	}
	state, e := db.Job(ctx, admin, id)
	if e != nil {
		t.Fatal(e)
	}
	var progress ReconciliationProgress
	json.Unmarshal(state.Target, &progress)
	if progress.Pages != 1 || progress.RetrievalsReleased != 1 || progress.AfterPath != "dead" {
		t.Fatalf("page did not checkpoint: %+v", progress)
	}
	if _, e = db.ControlJob(ctx, admin, "cancel-recovery", "cancel", id, "cancel", false); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ControlJob(ctx, admin, "resume-recovery", "resume", id, "retry", false); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 10; n++ {
		j, e = db.ClaimJob(ctx, worker, "maintenance", "node-b", time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		result, e := db.ReconcileLeases(ctx, worker, j)
		if e != nil {
			t.Fatal(e)
		}
		if result == "succeeded" {
			break
		}
		if n == 9 {
			t.Fatal("never finished")
		}
	}
	state, e = db.Job(ctx, admin, id)
	if e != nil || state.State != "succeeded" {
		t.Fatal(state, e)
	}
	json.Unmarshal(state.Target, &progress)
	if progress.RetrievalsReleased != 1 || progress.UploadOperationsReleased != 1 || progress.UploadsExpired != 1 || progress.Pages < 4 {
		t.Fatalf("wrong recovery totals: %+v", progress)
	}
	if e = db.CompleteRetrieval(ctx, admin, dead, RetrievalResult{Failure: "transient_upstream_failure"}); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("recovered retrieval completed", e)
	}
	if e = db.RenewRetrieval(ctx, admin, live, time.Minute); e != nil {
		t.Fatal("live retrieval changed", e)
	}
	l, e := db.Retrieval(ctx, admin, "source", late.Path)
	if e != nil || l.State != "fetching" || l.Generation != late.Generation {
		t.Fatal("after-cutoff work changed", l, e)
	}
	if e = db.RenewUpload(ctx, admin, current, time.Minute, time.Hour); e != nil {
		t.Fatal("live upload changed", e)
	}
	if e = acceptTestUpload(db, ctx, admin, old, UploadPart{Digest: strings.Repeat("d", 64), Size: 3}); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("recovered upload completed", e)
	}
	replacement := claimTestUpload(t, db, ctx, admin, "images", abandoned)
	if replacement.Offset != 0 || replacement.Generation <= old.Generation {
		t.Fatal("recovery lost offset or fence")
	}
	if _, e = db.Upload(ctx, admin, "images", "app", expired); !errors.Is(e, ErrNotFound) {
		t.Fatal("expired session resurrected", e)
	}
}
