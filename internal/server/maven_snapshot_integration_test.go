//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestMavenNonuniqueSnapshotsPreservePolicyHoldsReceiptsAndConfiguration(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	settings := store.RepositorySettings{MavenSnapshotPolicy: store.MavenSnapshotRedeployNonunique}
	mavenRepositories(t, s, admin,
		store.Repository{Name: "snapshots", Format: "maven", RequireReview: true, Access: "restricted", Settings: settings},
		store.Repository{Name: "immutable", Format: "maven"})
	credentials := map[string]string{}
	for _, actor := range []string{"publisher", "other-publisher", "consumer"} {
		value, e := crypt.Token()
		if e != nil {
			t.Fatal(e)
		}
		role := "writer"
		if actor == "consumer" {
			role = "reader"
		}
		if e = store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, role, value, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		credentials[actor] = value
		if e = s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'snapshots',$2,true,$3)`, admin.Tenant, actor, role == "writer")
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	p := "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar"
	a, b := "first owned snapshot bytes", "replacement owned snapshot bytes"
	for _, path := range []string{p, "org/example/tool/1.0/tool-1.0.jar", "org/example/tool/1.0-SNAPSHOT/tool-1.0-20261104.170000-1.jar"} {
		mavenPut(t, s, token, "immutable", path, a)
		if w := mavenHTTP(t, s, token, "PUT", "/r/immutable/"+path, b); w.Code != 409 {
			t.Fatal("default immutability changed", path, w.Code)
		}
	}
	for _, path := range []string{"org/example/tool/1.0/tool-1.0.jar", "org/example/tool/1.0-SNAPSHOT/tool-1.0-20261104.170000-1.jar"} {
		mavenPut(t, s, credentials["publisher"], "snapshots", path, a)
		if w := mavenHTTP(t, s, credentials["publisher"], "PUT", "/r/snapshots/"+path, b); w.Code != 409 {
			t.Fatal("snapshot opt-in made another coordinate mutable", path, w.Code)
		}
	}
	mavenPut(t, s, credentials["publisher"], "snapshots", p, a)
	decide := func(value, decision string) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := store.Decide(ctx, tx, admin, "snapshots", p, crypt.Digest([]byte(value)), decision)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	decide(a, "allowed")
	state := func() store.ArtifactState {
		t.Helper()
		value, e := s.DB.ArtifactState(ctx, admin, "snapshots", p)
		if e != nil {
			t.Fatal(e)
		}
		return value
	}
	changeState := func(action string, revision int64, digest string) error {
		_, e := s.DB.ChangeArtifactState(ctx, admin, "snapshots", "", "", store.ArtifactStateRequest{Path: p, Digest: digest, Action: action, ExpectedRevision: revision, Reason: "Owned snapshot regression"}, 100, nil)
		return e
	}
	if e := changeState("hold", 0, crypt.Digest([]byte(a))); e != nil {
		t.Fatal(e)
	}
	if w := mavenHTTP(t, s, credentials["publisher"], "PUT", "/r/snapshots/"+p, b); w.Code != 409 || !strings.Contains(w.Body.String(), "artifact_held") {
		t.Fatal("snapshot replacement crossed preservation", w.Code, w.Body.String())
	}
	mavenPut(t, s, credentials["publisher"], "snapshots", p, a)
	if got := state(); got.Revision != 1 || !got.Held || got.Digest != crypt.Digest([]byte(a)) {
		t.Fatal("same-byte retry changed held identity", got)
	}
	if e := changeState("release_hold", 1, crypt.Digest([]byte(a))); e != nil {
		t.Fatal(e)
	}
	before, _, e := s.DB.HoldHistory(ctx, admin, "snapshots", p, store.ListRequest{Limit: 100})
	if e != nil || len(before) != 2 {
		t.Fatal("hold receipts", before, e)
	}
	mavenPut(t, s, credentials["publisher"], "snapshots", p, b)
	if got := state(); got.Revision != 3 || got.Digest != crypt.Digest([]byte(b)) || got.Held {
		t.Fatal("replacement failed to advance lifecycle", got)
	}
	journalState := state()
	if e = s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT payload::jsonb#>'{data,reference_replacement}' FROM cratectl.events WHERE sequence=$1`, journalState.ChangeSequence).Scan(&raw); e != nil {
			return e
		}
		var replacement struct{ Previous, Current store.ArtifactState }
		if e := json.Unmarshal(raw, &replacement); e != nil {
			return e
		}
		if replacement.Previous.Digest != crypt.Digest([]byte(a)) || replacement.Previous.Revision != 2 || replacement.Current.Digest != crypt.Digest([]byte(b)) || replacement.Current.Revision != 3 {
			t.Fatal("publication lacks exact old/new lifecycle snapshot", replacement)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	after, _, e := s.DB.HoldHistory(ctx, admin, "snapshots", p, store.ListRequest{Limit: 100})
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if e != nil || string(beforeJSON) != string(afterJSON) {
		t.Fatal("replacement rewrote old hold receipts", e)
	}
	if w := mavenHTTP(t, s, credentials["consumer"], "GET", "/r/snapshots/"+p, ""); w.Code != 403 {
		t.Fatal("new bytes inherited old approval", w.Code)
	}
	decide(b, "allowed")
	if w := mavenHTTP(t, s, credentials["consumer"], "GET", "/r/snapshots/"+p, ""); w.Code != 200 || w.Body.String() != b {
		t.Fatal("approved replacement bytes differ", w.Code)
	}
	for _, request := range []struct {
		actor, body string
		status      int
	}{
		{"publisher", crypt.Digest([]byte(a)), 201},
		{"other-publisher", crypt.Digest([]byte(a)), 400},
		{"consumer", crypt.Digest([]byte(a)), 403},
		{"publisher", strings.Repeat("0", 64), 400},
	} {
		w := mavenHTTP(t, s, credentials[request.actor], "PUT", "/r/snapshots/"+p+".sha256", request.body)
		if w.Code != request.status {
			t.Fatal("delayed snapshot checksum lost publisher binding", request.actor, w.Code)
		}
	}
	if w := mavenHTTP(t, s, credentials["consumer"], "GET", "/r/snapshots/"+p+".sha256", ""); w.Code != 200 || w.Body.String() != crypt.Digest([]byte(b)) {
		t.Fatal("historical receipt changed current checksum", w.Code)
	}
	old, e := s.Blobs.OpenVerified(ctx, admin.Tenant, crypt.Digest([]byte(a)), int64(len(a)))
	if e != nil {
		t.Fatal("old immutable bytes lost", e)
	}
	retained, e := io.ReadAll(old)
	_ = old.Close()
	if e != nil || string(retained) != a {
		t.Fatal("old immutable bytes changed", e)
	}
	if e = changeState("delete", 2, crypt.Digest([]byte(a))); !errors.Is(e, store.ErrLifecycleRevision) {
		t.Fatal("stale lifecycle preview acted on replacement", e)
	}
	// Stage bytes while opt-in is active, then revoke it before publication.
	staged, e := s.Blobs.Put(ctx, admin.Tenant, strings.NewReader("staged before policy change"), "", -1)
	if e != nil {
		t.Fatal(e)
	}
	policyBody := `{"expected_revision":0,"settings":{"maven_snapshot_policy":"immutable"},"reason":"Stop nonunique replacement","dry_run":true}`
	w := mavenHTTP(t, s, token, "PUT", "/api/v1/repositories/snapshots/configuration", policyBody)
	var preview store.ConfigurationPreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.RefreshRequired || preview.NextRevision != 1 {
		t.Fatal("hosted policy preview", w.Code, w.Body.String())
	}
	policyBody = strings.Replace(policyBody, `"dry_run":true`, `"dry_run":false`, 1)
	w = mavenHTTP(t, s, token, "PUT", "/api/v1/repositories/snapshots/configuration", policyBody, "Idempotency-Key", "snapshot-policy-stop")
	if w.Code != 200 {
		t.Fatal("hosted policy apply", w.Code, w.Body.String())
	}
	if e = s.DB.PublishMavenSnapshot(ctx, admin, "snapshots", store.Artifact{Path: p, Digest: staged.Digest, Size: staged.Size}, nil); !errors.Is(e, store.ErrConflict) {
		t.Fatal("intake-time opt-in bypassed current policy", e)
	}
	if w = mavenHTTP(t, s, credentials["publisher"], "PUT", "/r/snapshots/"+p, "third snapshot"); w.Code != 409 {
		t.Fatal("disabled redeployment still changed bytes", w.Code)
	}
	if e = changeState("delete", 3, crypt.Digest([]byte(b))); e != nil {
		t.Fatal(e)
	}
	if w = mavenHTTP(t, s, credentials["publisher"], "PUT", "/r/snapshots/"+p, b); w.Code != 404 {
		t.Fatal("same-byte publication resurrected tombstone", w.Code)
	}
}

func TestMavenNonuniqueSnapshotQueueFailureRollsBackReferenceReceiptsAndLifecycle(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "snapshots", Format: "maven", Settings: store.RepositorySettings{MavenSnapshotPolicy: store.MavenSnapshotRedeployNonunique}})
	p, first, second := "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar", "original bytes", "rejected replacement"
	mavenPut(t, s, token, "snapshots", p, first)
	for n, action := range []string{"hold", "release_hold"} {
		if _, e := s.DB.ChangeArtifactState(ctx, admin, "snapshots", "", "", store.ArtifactStateRequest{Path: p, Digest: crypt.Digest([]byte(first)), Action: action, ExpectedRevision: int64(n), Reason: "Queue rollback regression"}, 100, nil); e != nil {
			t.Fatal(e)
		}
	}
	counts := func() [3]int64 {
		t.Helper()
		var out [3]int64
		if e := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.events),(SELECT count(*) FROM cratectl.jobs),(SELECT count(*) FROM cratectl.mutations)`).Scan(&out[0], &out[1], &out[2])
		}); e != nil {
			t.Fatal(e)
		}
		return out
	}
	before := counts()
	if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if w := mavenHTTP(t, s, token, "PUT", "/r/snapshots/"+p, second); w.Code != 503 || !strings.Contains(w.Body.String(), "durable_queue_full") {
		t.Fatal("full outbox accepted replacement", w.Code, w.Body.String())
	}
	if counts() != before {
		t.Fatal("failed replacement partially committed events/jobs/receipts")
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p, ""); w.Code != 200 || w.Body.String() != first {
		t.Fatal("failed replacement changed reference", w.Code)
	}
	if e := s.DB.MavenChecksumReceipt(ctx, admin, "snapshots", p, "sha256", crypt.Digest([]byte(second))); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("failed publication acquired a checksum receipt", e)
	}
	if state, e := s.DB.ArtifactState(ctx, admin, "snapshots", p); e != nil || state.Revision != 2 || state.Digest != crypt.Digest([]byte(first)) {
		t.Fatal("failed publication changed lifecycle identity", state, e)
	}
	// The immutable-policy first-publication branch also records receipts in the
	// same transaction; a full event queue must roll back both, including a new
	// reference that has no previous preservation state.
	mavenRepositories(t, s, admin, store.Repository{Name: "immutable", Format: "maven"})
	if w := mavenHTTP(t, s, token, "PUT", "/r/immutable/"+p, second); w.Code != 503 || !strings.Contains(w.Body.String(), "durable_queue_full") {
		t.Fatal("full outbox accepted immutable first publication", w.Code)
	}
	if counts() != before {
		t.Fatal("failed immutable publication partially committed events/jobs/receipts")
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/immutable/"+p, ""); w.Code != 404 {
		t.Fatal("failed immutable publication left a reference", w.Code)
	}
	if e := s.DB.MavenChecksumReceipt(ctx, admin, "immutable", p, "sha256", crypt.Digest([]byte(second))); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("failed immutable publication acquired a checksum receipt", e)
	}
}

func TestMavenImmutableSnapshotReceiptSurvivesLaterPolicyOptInAndAnotherPublisher(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "snapshots", Format: "maven"})
	p, first, second := "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar", "immutable original publication", "later opted-in publisher bytes"
	mavenPut(t, s, token, "snapshots", p, first)
	writer, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, database.OwnerDSN, admin.Tenant, "later-publisher", "writer", writer, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	body := `{"expected_revision":0,"settings":{"maven_snapshot_policy":"redeploy_nonunique"},"reason":"Enable explicitly after original immutable publication","dry_run":false}`
	if w := mavenHTTP(t, s, token, "PUT", "/api/v1/repositories/snapshots/configuration", body, "Idempotency-Key", "immutable-snapshot-receipt-opt-in"); w.Code != 200 {
		t.Fatal("later snapshot opt-in failed", w.Code)
	}
	mavenPut(t, s, writer, "snapshots", p, second)
	if w := mavenHTTP(t, s, token, "PUT", "/r/snapshots/"+p+".sha256", crypt.Digest([]byte(first))); w.Code != 201 {
		t.Fatal("original immutable publisher lost its historical receipt after opt-in", w.Code)
	}
	if w := mavenHTTP(t, s, writer, "PUT", "/r/snapshots/"+p+".sha256", crypt.Digest([]byte(first))); w.Code != 400 {
		t.Fatal("later publisher acquired another actor's original receipt", w.Code)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p+".sha256", ""); w.Code != 200 || w.Body.String() != crypt.Digest([]byte(second)) {
		t.Fatal("historical immutable receipt changed the current checksum", w.Code)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p, ""); w.Code != 200 || w.Body.String() != second {
		t.Fatal("historical checksum upload changed current bytes", w.Code)
	}
}

func TestMavenNonuniqueSnapshotPolicyAndReceiptsRemainTenantScoped(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "snapshots", Format: "maven", Settings: store.RepositorySettings{MavenSnapshotPolicy: store.MavenSnapshotRedeployNonunique}})
	other, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, database.OwnerDSN, "snapshot-tenant-b", admin.Actor, "admin", other, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	identity, e := s.DB.Authenticate(ctx, other)
	if e != nil {
		t.Fatal(e)
	}
	mavenRepositories(t, s, identity, store.Repository{Name: "snapshots", Format: "maven"})
	p := "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar"
	mavenPut(t, s, token, "snapshots", p, "tenant a original")
	mavenPut(t, s, token, "snapshots", p, "tenant a replacement")
	mavenPut(t, s, other, "snapshots", p, "tenant b immutable")
	if w := mavenHTTP(t, s, other, "PUT", "/r/snapshots/"+p, "tenant b replacement"); w.Code != 409 {
		t.Fatal("another tenant inherited snapshot opt-in", w.Code)
	}
	if w := mavenHTTP(t, s, other, "PUT", "/r/snapshots/"+p+".sha256", crypt.Digest([]byte("tenant a original"))); w.Code != 400 {
		t.Fatal("another tenant inherited historical checksum receipt", w.Code)
	}
	if w := mavenHTTP(t, s, other, "GET", "/r/snapshots/"+p, ""); w.Code != 200 || w.Body.String() != "tenant b immutable" {
		t.Fatal("tenant collision changed current bytes", w.Code)
	}
}

func TestMavenNonuniqueSnapshotConcurrentWritersKeepOneJournalChainAndTheirOwnReceipts(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "snapshots", Format: "maven", Access: "restricted", Settings: store.RepositorySettings{MavenSnapshotPolicy: store.MavenSnapshotRedeployNonunique}})
	p, seed := "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar", "original held and released snapshot"
	mavenPut(t, s, token, "snapshots", p, seed)
	for n, action := range []string{"hold", "release_hold"} {
		if _, e := s.DB.ChangeArtifactState(ctx, admin, "snapshots", "", "", store.ArtifactStateRequest{Path: p, Digest: crypt.Digest([]byte(seed)), Action: action, ExpectedRevision: int64(n), Reason: "Owned concurrent snapshot regression"}, 100, nil); e != nil {
			t.Fatal(e)
		}
	}
	before, _, e := s.DB.HoldHistory(ctx, admin, "snapshots", p, store.ListRequest{Limit: 100})
	if e != nil || len(before) != 2 {
		t.Fatal("initial preservation receipts", e)
	}
	type publisher struct {
		actor, token, body string
		identity           store.Identity
	}
	writers := []publisher{{actor: "snapshot-writer-a", body: "concurrent snapshot bytes A"}, {actor: "snapshot-writer-b", body: "concurrent snapshot bytes B"}}
	for n := range writers {
		w := &writers[n]
		if w.token, e = crypt.Token(); e != nil {
			t.Fatal(e)
		}
		if e = store.Provision(ctx, database.OwnerDSN, admin.Tenant, w.actor, "writer", w.token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		if w.identity, e = s.DB.Authenticate(ctx, w.token); e != nil {
			t.Fatal(e)
		}
		if e = s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'snapshots',$2,true,true)`, admin.Tenant, w.actor)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, len(writers))
	var ready sync.WaitGroup
	ready.Add(len(writers))
	for _, writer := range writers {
		go func() {
			ready.Done()
			<-start
			r := httptest.NewRequest("PUT", "/r/snapshots/"+p, strings.NewReader(writer.body))
			r.Header.Set("Authorization", "Bearer "+writer.token)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			results <- w
		}()
	}
	ready.Wait()
	close(start)
	for range writers {
		w := <-results
		if w.Code != 201 {
			t.Error("concurrent publication failed", w.Code, w.Body.String())
		}
	}
	if t.Failed() {
		return
	}
	current := mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p, "")
	if current.Code != 200 || current.Body.String() != writers[0].body && current.Body.String() != writers[1].body {
		t.Fatal("concurrent reference is not either complete publication", current.Code)
	}
	state, e := s.DB.ArtifactState(ctx, admin, "snapshots", p)
	if e != nil || state.Revision != 4 || state.Held || state.Digest != crypt.Digest(current.Body.Bytes()) {
		t.Fatal("concurrent lifecycle lost an update", state, e)
	}
	if e = s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT sequence,payload FROM cratectl.events WHERE payload::jsonb->>'kind'='maven.snapshot.published' AND payload::jsonb#>>'{data,repository}'='snapshots' AND payload::jsonb#>>'{data,path}'=$1 AND payload::jsonb#>'{data,reference_replacement}' IS NOT NULL ORDER BY sequence`, p)
		if e != nil {
			return e
		}
		defer rows.Close()
		previousDigest, previousRevision, changes := crypt.Digest([]byte(seed)), int64(2), 0
		for rows.Next() {
			var sequence int64
			var raw []byte
			if e = rows.Scan(&sequence, &raw); e != nil {
				return e
			}
			var event struct {
				Actor string
				Data  struct {
					Digest         string
					PreviousDigest string                                          `json:"previous_digest"`
					Replacement    struct{ Previous, Current store.ArtifactState } `json:"reference_replacement"`
				}
			}
			if e = json.Unmarshal(raw, &event); e != nil {
				return e
			}
			r := event.Data.Replacement
			if event.Data.PreviousDigest != previousDigest || r.Previous.Digest != previousDigest || r.Previous.Revision != previousRevision || r.Current.Revision != previousRevision+1 || r.Current.Digest != event.Data.Digest || r.Current.ChangeSequence != sequence || r.Current.Actor != event.Actor {
				t.Error("concurrent publication journal forked", sequence, event)
			}
			matched := false
			for _, writer := range writers {
				matched = matched || event.Actor == writer.actor && event.Data.Digest == crypt.Digest([]byte(writer.body))
			}
			if !matched {
				t.Error("journal publisher/digest identity differs")
			}
			previousDigest, previousRevision = event.Data.Digest, r.Current.Revision
			changes++
		}
		if rows.Err() != nil {
			return rows.Err()
		}
		if changes != 2 || previousDigest != state.Digest || previousRevision != state.Revision {
			t.Error("journal lost a concurrent replacement", changes)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	for _, writer := range writers {
		digest := crypt.Digest([]byte(writer.body))
		if e = s.DB.MavenChecksumReceipt(ctx, writer.identity, "snapshots", p, "sha256", digest); e != nil {
			t.Fatal("accepted writer lost its own checksum receipt", e)
		}
		if w := mavenHTTP(t, s, writer.token, "PUT", "/r/snapshots/"+p+".sha256", digest); w.Code != 201 {
			t.Fatal("delayed concurrent publisher sidecar rejected", w.Code)
		}
		f, e := s.Blobs.OpenVerified(ctx, admin.Tenant, digest, int64(len(writer.body)))
		if e != nil {
			t.Fatal("concurrent immutable bytes lost", e)
		}
		body, e := io.ReadAll(f)
		_ = f.Close()
		if e != nil || string(body) != writer.body {
			t.Fatal("concurrent immutable bytes changed", e)
		}
	}
	winner, loser := writers[0], writers[1]
	if current.Body.String() != winner.body {
		winner, loser = loser, winner
	}
	if w := mavenHTTP(t, s, winner.token, "PUT", "/r/snapshots/"+p+".sha256", crypt.Digest([]byte(loser.body))); w.Code != 400 {
		t.Fatal("concurrent publisher inherited the other writer's historical receipt", w.Code)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p+".sha256", ""); w.Code != 200 || w.Body.String() != state.Digest {
		t.Fatal("delayed sidecar changed the current checksum", w.Code)
	}
	after, _, e := s.DB.HoldHistory(ctx, admin, "snapshots", p, store.ListRequest{Limit: 100})
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if e != nil || string(a) != string(b) {
		t.Fatal("concurrent replacements rewrote preservation receipts", e)
	}
}
