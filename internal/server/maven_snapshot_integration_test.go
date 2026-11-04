//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
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
