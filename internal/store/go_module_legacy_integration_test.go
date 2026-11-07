//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func appendLegacyChecksumLabel(t *testing.T, f goIntakeFixture, beforeComplete func()) GoChecksumLegacyIncident {
	t.Helper()
	ctx := context.Background()
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "unattributed-observation", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if beforeComplete != nil {
		beforeComplete()
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork"}); err != nil {
		t.Fatal("label-only incident lost under ordinary queue pressure", err)
	}
	page, more, err := f.s.GoChecksumLegacyIncidentPage(ctx, f.i, 0, 100, "")
	if err != nil || more || len(page) != 1 {
		t.Fatal("unattributed incident lost", err, len(page))
	}
	if failures, forks := goFailureCounts(t, f); failures != 0 || forks != 0 {
		t.Fatal("a caller label manufactured signed proof or key attribution", failures, forks)
	}
	return page[0]
}

func TestGoModuleLegacyChecksumReviewFencesAndConcurrentLostResponses(t *testing.T) {
	f, _ := publishGoFailureFixture(t)
	ctx := context.Background()
	incident := appendLegacyChecksumLabel(t, f, nil)
	input := legacyChecksumReviewFor(t, f, incident)
	for _, scenario := range []string{"incident", "key", "checkpoint", "checkpoint-revision", "source", "acknowledgment", "reader", "cross-tenant"} {
		t.Run(scenario, func(t *testing.T) {
			bad, identity := input, f.i
			var want error = ErrGoChecksumLegacyChanged
			switch scenario {
			case "incident":
				bad.IncidentHash = strings.Repeat("0", 64)
			case "key":
				bad.KeyDigest = strings.Repeat("0", 64)
			case "checkpoint":
				bad.CheckpointSHA256 = strings.Repeat("0", 64)
			case "checkpoint-revision":
				bad.ExpectedCheckpointRevision++
			case "source":
				bad.ExpectedSourceRevision++
			case "acknowledgment":
				bad.AcceptUnattributedHistory = false
				want = ErrGoChecksumLegacyInput
			case "reader":
				identity.Role = "reader"
				identity.CredentialHash = ""
				want = ErrDenied
			case "cross-tenant":
				identity.Tenant = "unrelated-legacy"
				identity.CredentialHash = ""
				want = ErrNotFound
			}
			_, err := f.s.ReviewGoChecksumLegacyIncident(ctx, identity, "owned", incident.Sequence, "fenced-review-"+scenario, crypt.Digest([]byte(scenario)), bad)
			if !errors.Is(err, want) {
				t.Fatal("stale or unauthorized review accepted", err)
			}
		})
	}
	if a, b, _ := legacyReviewCounts(t, f); a != 0 || b != 0 {
		t.Fatal("rejected review left durable effects")
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, key := range []string{"concurrent-review-one", "concurrent-review-two"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			<-start
			_, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, key, crypt.Digest([]byte(key)), input)
			results <- err
		}(key)
	}
	close(start)
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal("concurrent review duplicated an incident disposition", ok, conflict)
	}
	if a, b, _ := legacyReviewCounts(t, f); a != 1 || b != 1 {
		t.Fatal("concurrent review lost atomic event/receipt", a, b)
	}
	receipt, err := f.s.GoChecksumLegacyReviewEvidence(ctx, f.i, incident.Sequence, input.KeyDigest)
	if err != nil || receipt.PackageAdmission || receipt.Review.IncidentHash != incident.EventHash || crypt.Digest(receipt.Checkpoint) != input.CheckpointSHA256 {
		t.Fatal("retained review lost original trust bindings", err)
	}
	if _, err = f.s.GoChecksumLegacyReviewEvidence(ctx, f.i, incident.Sequence, strings.Repeat("0", 64)); !errors.Is(err, ErrNotFound) {
		t.Fatal("another key inherited disposition", err)
	}
	other, _, _ := checksumPublicFixture(t)
	setGoChecksumAuthority(t, f, &other, true)
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 1)
	if err != nil || state.Blocked || !state.LegacyReviewRequired {
		t.Fatal("review silently transferred to a new key/source", err)
	}
	old, err := f.s.GoChecksumLegacyReviewEvidence(ctx, f.i, incident.Sequence, input.KeyDigest)
	if err != nil || !bytes.Equal(old.Checkpoint, receipt.Checkpoint) || old.Review != receipt.Review {
		t.Fatal("source change rewrote retained review", err)
	}
	secondKeyReview := legacyChecksumReviewFor(t, f, incident)
	if _, err = f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "review-second-exact-key", crypt.Digest([]byte("second exact key")), secondKeyReview); err != nil {
		t.Fatal("new key cannot obtain its own explicit disposition", err)
	}
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "another-unattributed-incident", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork"}); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{input.KeyDigest, secondKeyReview.KeyDigest} {
		items, more, err := f.s.GoChecksumLegacyIncidentPage(ctx, f.i, 0, 100, digest)
		if err != nil || more || len(items) != 2 || !items[0].ReviewedForKey || items[1].ReviewedForKey {
			t.Fatal("a past disposition approved another incident or key", err, items)
		}
	}
	state, err = f.s.GoChecksumState(ctx, f.i, "owned", 1)
	if err != nil || state.Blocked || !state.LegacyReviewRequired {
		t.Fatal("a later unattributed incident inherited older trust reviews", err)
	}
}

func TestGoModuleLegacyChecksumRetainedConfigurationRecoveryKeepsCreationAndForkGates(t *testing.T) {
	f, _ := publishGoFailureFixture(t)
	ctx := context.Background()
	incident := appendLegacyChecksumLabel(t, f, nil)
	old := legacyChecksumReviewFor(t, f, incident)
	r, err := f.s.Configuration(ctx, f.i, "owned")
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := checksumPublicFixture(t)
	settings := r.Settings
	settings.GoChecksumAuthority = &other
	settings.Cache.RequireChecksum = true
	input := ConfigurationRequest{ExpectedRevision: 0, Settings: &settings, Reason: "select separately trusted public key after unattributed incident", DryRun: true}
	if _, err = f.s.ChangeConfiguration(ctx, f.i, "owned", "", "", input, 100); err != nil {
		t.Fatal("retained trust recovery preview", err)
	}
	input.DryRun = false
	if _, err = f.s.ChangeConfiguration(ctx, f.i, "owned", "legacy-key-recovery", "legacy-key-recovery", input, 100); err != nil {
		t.Fatal("retained trust configuration could not advance", err)
	}
	if _, err = f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "old-preview-rejected", crypt.Digest([]byte("old preview")), old); !errors.Is(err, ErrGoChecksumLegacyChanged) {
		t.Fatal("source replacement accepted old review", err)
	}
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 1)
	if err != nil || state.Checkpoint.Revision != 0 || !state.LegacyReviewRequired || state.Blocked {
		t.Fatal("new source erased unknown incident or assumed old history", err)
	}
	r, err = f.s.Configuration(ctx, f.i, "owned")
	if err != nil {
		t.Fatal(err)
	}
	proposed := r
	proposed.Name = "new-public-proxy"
	proposed.SourceRevision = 0
	if err = ValidateRepository(&proposed); err == nil {
		t.Fatal("configuration recovery enabled public proxy creation")
	}
	settings.GoChecksumAuthority = nil
	input.ExpectedRevision = 1
	if _, err = f.s.ChangeConfiguration(ctx, f.i, "owned", "disable-checksum", "disable-checksum", input, 100); !errors.Is(err, ErrConfigurationInput) {
		t.Fatal("recovery disabled checksum authority", err)
	}
	settings.GoChecksumAuthority = &other
	settings.Cache.RequireChecksum = false
	if _, err = f.s.ChangeConfiguration(ctx, f.i, "owned", "disable-enforcement", "disable-enforcement", input, 100); !errors.Is(err, ErrConfigurationInput) {
		t.Fatal("recovery disabled checksum enforcement", err)
	}
}

func TestGoModuleLegacyChecksumConcurrentForkAlwaysOverridesExternalReview(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	r, err := f.s.Repository(ctx, f.i, "owned")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(r.Settings)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,settings)VALUES($1,'fork-observer','go','proxy',$2)`, f.i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "fork-observer", f.lease.Path, "inflight-fork-observation", false)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	incident := appendLegacyChecksumLabel(t, f, nil)
	input := legacyChecksumReviewFor(t, f, incident)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "concurrent-fork-review", crypt.Digest([]byte("concurrent fork review")), input)
		results <- err
	}()
	go func() {
		<-start
		results <- f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}})
	}()
	close(start)
	for n := 0; n < 2; n++ {
		if err := <-results; err != nil && !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
			t.Fatal("concurrent fail-stop lost evidence or accepted invalid effect", err)
		}
	}
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 0)
	if err != nil || !state.Blocked || state.Checkpoint.Revision != 2 || !bytes.Equal(state.Checkpoint.Checkpoint, log.One) {
		t.Fatal("external review cleared concurrently authenticated fork", err)
	}
	if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("concurrent review admitted blocked authority", err)
	}
	if a, b, _ := legacyReviewCounts(t, f); a != b || a > 1 {
		t.Fatal("concurrent fork/review partial journal effect", a, b)
	}
	if a, b := goFailureCounts(t, f); a != 1 || b != 1 {
		t.Fatal("concurrent review erased authenticated fork evidence", a, b)
	}
}

func legacyChecksumReviewFor(t *testing.T, f goIntakeFixture, incident GoChecksumLegacyIncident) GoChecksumLegacyReviewRequest {
	t.Helper()
	r, err := f.s.Repository(context.Background(), f.i, "owned")
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.s.GoChecksumState(context.Background(), f.i, "owned", r.SourceRevision)
	if err != nil || state.Blocked || !state.LegacyReviewRequired {
		t.Fatal("unattributed label was hidden or promoted to proof", err)
	}
	return GoChecksumLegacyReviewRequest{AcceptUnattributedHistory: true, IncidentHash: incident.EventHash, ExpectedSourceRevision: r.SourceRevision, KeyDigest: state.Checkpoint.KeyDigest, ExpectedCheckpointRevision: state.Checkpoint.Revision, CheckpointSHA256: state.CheckpointSHA256, ReviewReferenceSHA256: crypt.Digest([]byte("owned separate external trust review")), Reason: "Explicit review of an external key; original incident attribution remains unknown"}
}

func legacyReviewCounts(t *testing.T, f goIntakeFixture) (reviews, journal, eventJobs int) {
	t.Helper()
	ctx := context.Background()
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.go_checksum_legacy_reviews),(SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='go.checksum.legacy.reviewed'),(SELECT count(*) FROM cratectl.jobs WHERE queue='events')`).Scan(&reviews, &journal, &eventJobs)
	}); err != nil {
		t.Fatal(err)
	}
	return
}

func TestGoModuleLegacyChecksumIncidentBlocksEveryKeyWorkAndBytePathWithoutInventingProof(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	prior := verifyStoredGoChecksum(t, f, view)
	incident := appendLegacyChecksumLabel(t, f, nil)
	evidence, err := f.s.GoChecksumLegacyIncidentEvidence(ctx, f.i, incident.Sequence)
	if err != nil || evidence.Classification != "unattributed_fork_label" || evidence.OriginalEvent.Hash != incident.EventHash || !strings.Contains(evidence.OriginalEvent.Payload, "upstream_checksum_fork") {
		t.Fatal("original immutable incident was rewritten or became proof", err)
	}
	if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0); !errors.Is(err, ErrGoChecksumLegacyReview) {
		t.Fatal("legacy incident admitted new collection", err)
	}
	if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, 0, prior.NativeAdmission()); !errors.Is(err, ErrGoChecksumLegacyReview) {
		t.Fatal("legacy incident admitted a pre-read package", err)
	}
	if _, err = f.s.GoModuleView(ctx, f.i, "owned", log.Module, 100, 1<<20); !errors.Is(err, ErrGoChecksumLegacyReview) {
		t.Fatal("legacy incident remained discoverable", err)
	}
	c, err := gomodule.Canonical(log.Module, "v1.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if absent, err := f.s.GoModuleProxyAbsent(ctx, f.i, "owned", c.Prefix()+".zip", 0); !errors.Is(err, ErrGoChecksumLegacyReview) || absent {
		t.Fatal("legacy incident allowed negative fallback", err)
	}
	if lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", c.Prefix()+".zip", "blocked-legacy-fill", false); !errors.Is(err, ErrGoChecksumLegacyReview) || lease.Acquired {
		t.Fatal("legacy incident started work", err)
	}
	if err = f.s.RenewRetrieval(ctx, f.i, f.lease, time.Minute); !errors.Is(err, ErrGoChecksumLegacyReview) {
		t.Fatal("legacy incident renewed upstream work", err)
	}
	other, _, _ := checksumPublicFixture(t)
	setGoChecksumAuthority(t, f, &other, true)
	if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 1); !errors.Is(err, ErrGoChecksumLegacyReview) {
		t.Fatal("unknown original key was assumed to be the old current key", err)
	}
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 1)
	if err != nil || state.Blocked || !state.LegacyReviewRequired || state.Checkpoint.Revision != 0 {
		t.Fatal("key/source switch cleared an unattributed incident or manufactured history", err)
	}
}

func TestGoModuleLegacyChecksumExternalReviewIsAtomicIdempotentAndCannotClearAFutureFork(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	incident := appendLegacyChecksumLabel(t, f, func() {
		for _, queue := range []string{"events", "integrity"} {
			if _, err := f.s.SetQueuePolicy(ctx, f.i, "legacy-full-"+queue, "legacy-full-"+queue, QueuePolicy{Queue: queue, Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
				t.Fatal(err)
			}
		}
	})
	input := legacyChecksumReviewFor(t, f, incident)
	preview := input
	preview.DryRun = true
	preview.AcceptUnattributedHistory = false
	if _, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "", "", preview); err != nil {
		t.Fatal("read-only explicit preview", err)
	}
	beforeReviews, beforeJournal, beforeJobs := legacyReviewCounts(t, f)
	if beforeReviews != 0 || beforeJournal != 0 {
		t.Fatal("preview mutated review state")
	}
	fingerprint := crypt.Digest([]byte("owned legacy review exact intent"))
	result, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "legacy-review-once", fingerprint, input)
	if err != nil || result.Replay {
		t.Fatal("review depends on ordinary queue capacity", err)
	}
	var receipt struct {
		Review           GoChecksumLegacyReview `json:"review"`
		PackageAdmission bool                   `json:"package_admission"`
	}
	if json.Unmarshal(result.Body, &receipt) != nil || receipt.PackageAdmission || receipt.Review.IncidentHash != incident.EventHash || receipt.Review.IncidentSequence != incident.Sequence || receipt.Review.Sequence <= incident.Sequence || receipt.Review.CheckpointRevision != 2 || receipt.Review.ReviewReferenceSHA256 != input.ReviewReferenceSHA256 {
		t.Fatal("review receipt invented admission or lost exact incident/trust bindings")
	}
	replayed, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "legacy-review-once", fingerprint, input)
	if err != nil || !replayed.Replay || !bytes.Equal(result.Body, replayed.Body) {
		t.Fatal("lost review response did not preserve exact idempotent receipt", err)
	}
	if _, err = f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "legacy-review-duplicate", crypt.Digest([]byte("other intent")), input); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate disposition created another effect", err)
	}
	if a, b, c := legacyReviewCounts(t, f); a != 1 || b != 1 || c != beforeJobs {
		t.Fatal("review/journal/receipt/outbox effect not atomic and queue-independent", a, b, c)
	}
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 0)
	if err != nil || state.Blocked || state.LegacyReviewRequired || state.Checkpoint.Revision != 2 || !bytes.Equal(state.Checkpoint.Checkpoint, log.One) {
		t.Fatal("review reset trust or invented a cryptographic fork", err)
	}
	if _, err = f.s.GoModuleChecksumReadback(ctx, f.i, "owned", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, 0); err == nil {
		t.Fatal("review alone admitted the failed module")
	}
	for _, queue := range []string{"events", "integrity"} {
		if _, err := f.s.SetQueuePolicy(ctx, f.i, "legacy-restore-"+queue, "legacy-restore-"+queue, QueuePolicy{Queue: queue, Capacity: 1024, MaxRunning: 32, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "genuine-new-proof", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, f.result); err != nil {
		t.Fatal("genuine normal proof cannot recover the reviewed key", err)
	}
	lease, err = f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "future-authenticated-fork", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "cannot-rehabilitate-key", crypt.Digest([]byte("new review")), input); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("administrative review cleared an authenticated fork", err)
	}
	old, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "legacy-review-once", fingerprint, input)
	if err != nil || !old.Replay {
		t.Fatal("historical review receipt was lost", err)
	}
	state, err = f.s.GoChecksumState(ctx, f.i, "owned", 0)
	if err != nil || !state.Blocked {
		t.Fatal("replaying old review rehabilitated a proved key fork", err)
	}
	if a, b, _ := legacyReviewCounts(t, f); a != 1 || b != 1 {
		t.Fatal("future fork or replay duplicated/rewrote the old disposition")
	}
}

func TestGoModuleLegacyChecksumRuntimeImmutabilityAndUnscopedRLS(t *testing.T) {
	f, _ := publishGoFailureFixture(t)
	ctx := context.Background()
	incident := appendLegacyChecksumLabel(t, f, nil)
	input := legacyChecksumReviewFor(t, f, incident)
	if _, err := f.s.ReviewGoChecksumLegacyIncident(ctx, f.i, "owned", incident.Sequence, "immutable-legacy-review", crypt.Digest([]byte("immutable legacy review")), input); err != nil {
		t.Fatal(err)
	}
	conn, err := f.s.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, table := range []string{"go_checksum_legacy_incidents", "go_checksum_legacy_reviews"} {
		var visible int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{"cratectl", table}.Sanitize()).Scan(&visible); err != nil || visible != 0 {
			t.Fatal("unscoped legacy evidence leaked", table, visible, err)
		}
		for _, sql := range []string{`DELETE FROM ` + pgx.Identifier{"cratectl", table}.Sanitize() + ` WHERE false`, `UPDATE ` + pgx.Identifier{"cratectl", table}.Sanitize() + ` SET event_sequence=event_sequence WHERE false`} {
			err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql); return err })
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Fatal("runtime can erase or rewrite legacy incident/review", table, err)
			}
		}
	}
}

func TestGoModuleLegacyChecksumRuntimeRefusesEitherUnforcedEvidenceTable(t *testing.T) {
	f, _ := publishGoFailureFixture(t)
	ctx := context.Background()
	owner, err := pgx.Connect(ctx, f.d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	for _, table := range []string{"go_checksum_legacy_incidents", "go_checksum_legacy_reviews"} {
		name := pgx.Identifier{"cratectl", table}.Sanitize()
		if _, err = owner.Exec(ctx, `ALTER TABLE `+name+` NO FORCE ROW LEVEL SECURITY`); err != nil {
			t.Fatal(err)
		}
		opened, err := Open(ctx, f.d.RuntimeDSN)
		if err == nil {
			opened.Pool.Close()
			t.Fatal("runtime admitted unforced legacy evidence", table)
		}
		if !errors.Is(err, ErrSchemaIncompatible) {
			t.Fatal("unforced table did not reach schema safety refusal", table, err)
		}
		if _, err = owner.Exec(ctx, `ALTER TABLE `+name+` FORCE ROW LEVEL SECURITY`); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := Open(ctx, f.d.RuntimeDSN)
	if err != nil {
		t.Fatal("runtime could not resume after owned safety fixture restoration", err)
	}
	opened.Pool.Close()
}
