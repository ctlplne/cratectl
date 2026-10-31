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
	"github.com/jackc/pgx/v5"
)

func retentionFixture(t *testing.T) (*Store, context.Context, Identity, WorkerIdentity, *pgx.Conn) {
	t.Helper()
	_, db, owner, token, workerToken := schemaFixture(t)
	ctx := context.Background()
	admin, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := db.AuthenticateWorker(ctx, workerToken)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, admin, Repository{Name: "retained", Format: "oci"})
	}); e != nil {
		t.Fatal(e)
	}
	return db, ctx, admin, worker, owner
}
func retentionManifest(t *testing.T, db *Store, ctx context.Context, i Identity, image, label string, age int64, parents []string) Artifact {
	t.Helper()
	digest := crypt.Digest([]byte(label))
	a := Artifact{Path: image + "/manifests/sha256:" + digest, Digest: digest, Size: 123, MediaType: integrationOCIImage}
	raw, _ := json.Marshal(OCIManifestMetadata{Validated: true, References: parents})
	e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,created_at)VALUES($1,'retained',$2,$3,123,$4,$5,clock_timestamp()-$6*interval '1 second')`, i.Tenant, a.Path, a.Digest, a.MediaType, raw, age)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func retentionPolicyInput() RetentionPolicyRequest {
	return RetentionPolicyRequest{RetentionSettings: RetentionSettings{MinAgeSeconds: 60, KeepLast: 0, ProtectTagged: true, Enabled: true, Reason: "Owned retained retirement regression"}}
}
func retentionConfigure(t *testing.T, db *Store, ctx context.Context, i Identity, r RetentionPolicyRequest) {
	t.Helper()
	if _, e := db.SetRetentionPolicy(ctx, i, "retained", "age", "policy-config-"+r.Reason, r.Reason, r); e != nil {
		t.Fatal(e)
	}
}
func retentionPreviewFixture(t *testing.T, db *Store, ctx context.Context, i Identity) RetentionPlan {
	t.Helper()
	result, e := db.StartRetention(ctx, i, "retained", "age", "", "", RetentionRequest{ExpectedRevision: 1, Reason: "Owned explicit approved retirement", DryRun: true}, 100)
	if e != nil {
		t.Fatal(e)
	}
	var p RetentionPlan
	if json.Unmarshal(result.Body, &p) != nil {
		t.Fatal(string(result.Body))
	}
	return p
}
func retentionAdmit(t *testing.T, db *Store, ctx context.Context, i Identity, p RetentionPlan, key string) string {
	t.Helper()
	r := RetentionRequest{ExpectedRevision: p.Policy.Revision, EvaluatedAt: &p.EvaluatedAt, PreviewDigest: p.Digest, Reason: p.Reason}
	v, e := db.StartRetention(ctx, i, "retained", "age", key, key, r, 100)
	if e != nil {
		t.Fatal(e)
	}
	var response struct {
		Job string `json:"job"`
	}
	if json.Unmarshal(v.Body, &response) != nil || response.Job == "" {
		t.Fatal(string(v.Body))
	}
	return response.Job
}
func retentionDrain(t *testing.T, db *Store, ctx context.Context, w WorkerIdentity, id string) {
	t.Helper()
	for n := 0; n < 100; n++ {
		j, e := db.ClaimJob(ctx, w, "maintenance", "retention-fixture", time.Minute)
		if e != nil || j.ID() != id {
			t.Fatal(j, e)
		}
		state, e := db.StepRetention(ctx, w, j)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.StepRetention(ctx, w, j); !errors.Is(e, ErrJobLeaseLost) {
			t.Fatal("stale effect fence accepted", e)
		}
		if state == "succeeded" {
			return
		}
	}
	t.Fatal("retention did not finish")
}
func retentionCount(t *testing.T, db *Store, ctx context.Context, i Identity, table string) int {
	t.Helper()
	var n int
	e := db.Tx(ctx, i, false, func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&n) })
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func TestRetentionPolicyPreviewRevisionHistoryAndBudget(t *testing.T) {
	db, ctx, admin, _, owner := retentionFixture(t)
	r := retentionPolicyInput()
	r.DryRun = true
	if _, e := db.SetRetentionPolicy(ctx, admin, "retained", "age", "", "", r); e != nil {
		t.Fatal(e)
	}
	if retentionCount(t, db, ctx, admin, "retention_policies") != 0 {
		t.Fatal("preview persisted configuration")
	}
	r.DryRun = false
	retentionConfigure(t, db, ctx, admin, r)
	if _, e := db.SetRetentionPolicy(ctx, admin, "retained", "age", "policy-config-"+r.Reason, r.Reason, r); e != nil {
		t.Fatal("idempotency", e)
	}
	if _, e := db.SetRetentionPolicy(ctx, admin, "retained", "age", "stale-config", "stale-config", r); !errors.Is(e, ErrRetentionChanged) {
		t.Fatal("stale revision", e)
	}
	for n, label := range []string{"one", "two", "three"} {
		retentionManifest(t, db, ctx, admin, "app", label, int64(100+n), nil)
	}
	preview := retentionPreviewFixture(t, db, ctx, admin)
	if preview.Eligible != 3 || preview.Targets != 3 || preview.BytesReclaimed != 0 {
		t.Fatal(preview)
	}
	_, e := db.StartRetention(ctx, admin, "retained", "age", "", "", RetentionRequest{ExpectedRevision: 1, Reason: preview.Reason, DryRun: true}, 2)
	if !errors.Is(e, ErrRetentionBudget) {
		t.Fatal("truncated retirement plan", e)
	}
	if retentionCount(t, db, ctx, admin, "retention_runs") != 0 {
		t.Fatal("preview admitted work")
	}
	readerToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = Provision(ctx, owner.Config().ConnString(), admin.Tenant, "reader", "reader", readerToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	reader, e := db.Authenticate(ctx, readerToken)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.RetentionPolicy(ctx, reader, "retained", "age"); !errors.Is(e, ErrDenied) {
		t.Fatal("reader policy", e)
	}
	if retentionCount(t, db, ctx, admin, "retention_revisions") != 1 {
		t.Fatal("configuration history")
	}
}
func TestRetentionPlanDigestRejectsChangedMembershipAndExpiredPreview(t *testing.T) {
	db, ctx, admin, _, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	retentionManifest(t, db, ctx, admin, "app", "one", 3600, nil)
	p := retentionPreviewFixture(t, db, ctx, admin)
	retentionManifest(t, db, ctx, admin, "app", "two", 3600, nil)
	r := RetentionRequest{ExpectedRevision: 1, EvaluatedAt: &p.EvaluatedAt, PreviewDigest: p.Digest, Reason: p.Reason}
	if _, e := db.StartRetention(ctx, admin, "retained", "age", "changed-plan", "changed-plan", r, 100); !errors.Is(e, ErrRetentionChanged) {
		t.Fatal("changed membership admitted", e)
	}
	old := time.Now().Add(-6 * time.Minute)
	r.EvaluatedAt = &old
	if _, e := db.StartRetention(ctx, admin, "retained", "age", "expired-plan", "expired-plan", r, 100); !errors.Is(e, ErrRetentionChanged) {
		t.Fatal("expired preview admitted", e)
	}
	if retentionCount(t, db, ctx, admin, "retention_runs") != 0 {
		t.Fatal("rejected plan persisted work")
	}
}
func TestRetentionKeepsNewestTagsHoldsParentsAndUnvalidatedContent(t *testing.T) {
	db, ctx, admin, w, _ := retentionFixture(t)
	input := retentionPolicyInput()
	input.KeepLast = 1
	retentionConfigure(t, db, ctx, admin, input)
	old := retentionManifest(t, db, ctx, admin, "app", "old", 3600, nil)
	retentionManifest(t, db, ctx, admin, "app", "newest", 120, nil)
	held := retentionManifest(t, db, ctx, admin, "hold", "held", 3600, nil)
	retentionManifest(t, db, ctx, admin, "hold", "held-new", 120, nil)
	if _, e := db.ChangeArtifactState(ctx, admin, "retained", "hold-before-plan", "hold-before-plan", lifecycleInput(held, "hold", 0), 100, nil); e != nil {
		t.Fatal(e)
	}
	tagged := retentionManifest(t, db, ctx, admin, "tagged", "tagged-old", 3600, nil)
	retentionManifest(t, db, ctx, admin, "tagged", "tagged-new", 120, nil)
	child := retentionManifest(t, db, ctx, admin, "child", "child-old", 3600, nil)
	retentionManifest(t, db, ctx, admin, "child", "child-new", 120, nil)
	retentionManifest(t, db, ctx, admin, "parent", "parent", 3600, []string{child.Path})
	legacy := retentionManifest(t, db, ctx, admin, "legacy", "legacy", 3600, nil)
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata='{}'::jsonb WHERE repository='retained' AND path=$1`, legacy.Path); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.tags(tenant,repository,image,tag,digest)VALUES($1,'retained','tagged','stable',$2)`, admin.Tenant, "sha256:"+tagged.Digest)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	p := retentionPreviewFixture(t, db, ctx, admin)
	statuses := map[string]string{}
	for _, item := range p.Items {
		statuses[item.Path] = item.Status
	}
	for path, want := range map[string]string{old.Path: "eligible", held.Path: "held", tagged.Path: "tagged", child.Path: "referenced", legacy.Path: "unvalidated"} {
		if statuses[path] != want {
			t.Fatal(path, statuses[path], want)
		}
	}
	id := retentionAdmit(t, db, ctx, admin, p, "protection-run")
	retentionDrain(t, db, ctx, w, id)
	state, e := db.ArtifactState(ctx, admin, "retained", old.Path)
	if e != nil || !state.Deleted {
		t.Fatal(state, e)
	}
	for _, a := range []Artifact{held, tagged, child, legacy} {
		state, e = db.ArtifactState(ctx, admin, "retained", a.Path)
		if e != nil || state.Deleted {
			t.Fatal("protected target retired", a.Path, state, e)
		}
	}
	run, e := db.RetentionRun(ctx, admin, id)
	if e != nil || run["retired"] != int64(1) || run["all_targets_processed"] != true || run["bytes_reclaimed"] != 0 {
		t.Fatal(run, e)
	}
	items, more, e := db.RetentionItems(ctx, admin, id, 0, 100)
	if e != nil || more || len(items) != p.Targets {
		t.Fatal(items, more, e)
	}
	raw, _ := json.Marshal(run)
	if strings.Contains(string(raw), admin.CredentialHash) {
		t.Fatal("requester execution fence exposed")
	}
	if _, e = db.ControlJob(ctx, admin, "retry-completed", "retry-completed", id, "retry", false); e != nil {
		t.Fatal(e)
	}
	retentionDrain(t, db, ctx, w, id)
	state, e = db.ArtifactState(ctx, admin, "retained", old.Path)
	if e != nil || state.Revision != 1 {
		t.Fatal("completed retry repeated retirement", state, e)
	}
}
func TestRetentionExecutionRechecksLateHoldsTagsAndParentsAndIgnoresMutableJobAuthority(t *testing.T) {
	db, ctx, admin, w, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	held := retentionManifest(t, db, ctx, admin, "hold", "late-held", 3600, nil)
	tagged := retentionManifest(t, db, ctx, admin, "tag", "late-tag", 3600, nil)
	child := retentionManifest(t, db, ctx, admin, "child", "late-parent-child", 3600, nil)
	plain := retentionManifest(t, db, ctx, admin, "plain", "plain", 3600, nil)
	p := retentionPreviewFixture(t, db, ctx, admin)
	id := retentionAdmit(t, db, ctx, admin, p, "late-protections")
	if _, e := db.ChangeArtifactState(ctx, admin, "retained", "late-hold", "late-hold", lifecycleInput(held, "hold", 0), 100, nil); e != nil {
		t.Fatal(e)
	}
	retentionManifest(t, db, ctx, admin, "new-parent", "unapproved-parent", 3600, []string{child.Path})
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.tags(tenant,repository,image,tag,digest)VALUES($1,'retained','tag','stable',$2)`, admin.Tenant, "sha256:"+tagged.Digest); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET payload='{}'::jsonb WHERE kind='repository.retention'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	retentionDrain(t, db, ctx, w, id)
	out, _, e := db.RetentionItems(ctx, admin, id, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	statuses := map[string]string{}
	for _, item := range out {
		statuses[item.Path] = item.Outcome
	}
	for path, want := range map[string]string{held.Path: "held", tagged.Path: "tagged", child.Path: "referenced", plain.Path: "retired"} {
		if statuses[path] != want {
			t.Fatal(path, statuses[path], want)
		}
	}
}
func TestRetentionRequesterAndPolicyChangesStopUnprocessedEffects(t *testing.T) {
	for _, fault := range []string{"requester", "policy"} {
		t.Run(fault, func(t *testing.T) {
			db, ctx, admin, w, owner := retentionFixture(t)
			retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
			a := retentionManifest(t, db, ctx, admin, "app", "stopped", 3600, nil)
			id := retentionAdmit(t, db, ctx, admin, retentionPreviewFixture(t, db, ctx, admin), "authority-fence")
			if fault == "requester" {
				if _, e := owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, admin.CredentialHash); e != nil {
					t.Fatal(e)
				}
			} else {
				r := retentionPolicyInput()
				r.ExpectedRevision = 1
				r.Reason = "Changed retention policy"
				retentionConfigure(t, db, ctx, admin, r)
			}
			j, e := db.ClaimJob(ctx, w, "maintenance", "fenced-worker", time.Minute)
			if e != nil || j.ID() != id {
				t.Fatal(j, e)
			}
			_, e = db.StepRetention(ctx, w, j)
			want := ErrRetentionChanged
			if fault == "requester" {
				want = ErrRetentionAuthorization
			}
			if !errors.Is(e, want) {
				t.Fatal("authority changed", e)
			}
			var deleted bool
			if e = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle WHERE tenant=$1 AND repository='retained' AND path=$2 AND deleted)`, admin.Tenant, a.Path).Scan(&deleted); e != nil || deleted {
				t.Fatal("unauthorized retirement", deleted, e)
			}
		})
	}
}
func TestRetentionTargetJournalFailureAndLateRequesterExpiryRollbackTogether(t *testing.T) {
	for _, fault := range []string{"journal", "late_expiry"} {
		t.Run(fault, func(t *testing.T) {
			db, ctx, admin, w, owner := retentionFixture(t)
			retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
			a := retentionManifest(t, db, ctx, admin, "app", "rollback", 3600, nil)
			id := retentionAdmit(t, db, ctx, admin, retentionPreviewFixture(t, db, ctx, admin), "rollback-retention")
			body := `IF NEW.payload::jsonb->>'kind'='repository.retention.target' THEN RAISE EXCEPTION 'owned retention journal fault'; END IF;`
			if fault == "late_expiry" {
				body = `IF NEW.payload::jsonb->>'kind'='repository.retention.succeeded' THEN UPDATE cratectl_private.tokens SET expires_at='epoch' WHERE hash='` + admin.CredentialHash + `'; END IF;`
			}
			if _, e := owner.Exec(ctx, `CREATE FUNCTION public.retention_fault()RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN `+body+` RETURN NEW; END$$; CREATE TRIGGER retention_fault BEFORE INSERT ON cratectl.events FOR EACH ROW EXECUTE FUNCTION public.retention_fault()`); e != nil {
				t.Fatal(e)
			}
			j, e := db.ClaimJob(ctx, w, "maintenance", "rollback-worker", time.Minute)
			if e != nil || j.ID() != id {
				t.Fatal(j, e)
			}
			if _, e = db.StepRetention(ctx, w, j); e == nil {
				t.Fatal("effect acknowledged without authority/journal")
			} else if fault == "late_expiry" && !errors.Is(e, ErrRetentionAuthorization) {
				t.Fatal(e)
			}
			state, e := db.ArtifactState(ctx, admin, "retained", a.Path)
			if e != nil || state.Deleted || state.Revision != 0 {
				t.Fatal("tombstone survived rollback", state, e)
			}
			if retentionCount(t, db, ctx, admin, "retention_observations") != 0 {
				t.Fatal("outcome survived rollback")
			}
			if _, e = owner.Exec(ctx, `DROP TRIGGER retention_fault ON cratectl.events; DROP FUNCTION public.retention_fault()`); e != nil {
				t.Fatal(e)
			}
			if state, e := db.StepRetention(ctx, w, j); e != nil || state != "succeeded" {
				t.Fatal("same fenced attempt could not recover", state, e)
			}
		})
	}
}

func TestRetentionUnprotectedApprovalDoesNotRetireANewTagBinding(t *testing.T) {
	db, ctx, admin, w, _ := retentionFixture(t)
	r := retentionPolicyInput()
	r.ProtectTagged = false
	retentionConfigure(t, db, ctx, admin, r)
	a := retentionManifest(t, db, ctx, admin, "app", "new-tag-after-approval", 3600, nil)
	id := retentionAdmit(t, db, ctx, admin, retentionPreviewFixture(t, db, ctx, admin), "new-tag-fence")
	if e := db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.tags(tenant,repository,image,tag,digest)VALUES($1,'retained','app','new-release',$2)`, admin.Tenant, "sha256:"+a.Digest)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	retentionDrain(t, db, ctx, w, id)
	state, e := db.ArtifactState(ctx, admin, "retained", a.Path)
	if e != nil || state.Deleted {
		t.Fatal("retirement hid a tag binding absent from its approved plan", state, e)
	}
	items, _, e := db.RetentionItems(ctx, admin, id, 0, 100)
	if e != nil || len(items) != 1 || items[0].Outcome != "changed" {
		t.Fatal(items, e)
	}
}

func TestRetentionRunAndExecutionRollBackWhenOutboxIsFull(t *testing.T) {
	db, ctx, admin, w, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	a := retentionManifest(t, db, ctx, admin, "app", "queue-rollback", 3600, nil)
	p := retentionPreviewFixture(t, db, ctx, admin)
	setCapacity := func(capacity int) {
		t.Helper()
		_, e := db.SetQueuePolicy(ctx, admin, "", "", QueuePolicy{Queue: "events", Capacity: capacity, MaxRunning: 1, MaxAttempts: 5, RetrySeconds: 1, RetryMaxSeconds: 5})
		if e != nil {
			t.Fatal(e)
		}
	}
	setCapacity(1)
	r := RetentionRequest{ExpectedRevision: 1, EvaluatedAt: &p.EvaluatedAt, PreviewDigest: p.Digest, Reason: p.Reason}
	if _, e := db.StartRetention(ctx, admin, "retained", "age", "full-outbox", "full-outbox", r, 100); !errors.Is(e, ErrQueueFull) {
		t.Fatal("admission ignored full outbox", e)
	}
	if retentionCount(t, db, ctx, admin, "retention_runs") != 0 || retentionCount(t, db, ctx, admin, "retention_items") != 0 {
		t.Fatal("run or targets survived rejected outbox")
	}
	setCapacity(100)
	id := retentionAdmit(t, db, ctx, admin, p, "full-outbox")
	j, e := db.ClaimJob(ctx, w, "maintenance", "queue-fence", time.Minute)
	if e != nil || j.ID() != id {
		t.Fatal("claim", e)
	}
	setCapacity(1)
	if _, e = db.StepRetention(ctx, w, j); !errors.Is(e, ErrQueueFull) {
		t.Fatal("target ignored full outbox", e)
	}
	state, e := db.ArtifactState(ctx, admin, "retained", a.Path)
	if e != nil || state.Deleted || retentionCount(t, db, ctx, admin, "retention_observations") != 0 {
		t.Fatal("partial retirement survived full outbox", state, e)
	}
	setCapacity(100)
	if state, e := db.StepRetention(ctx, w, j); e != nil || state != "succeeded" {
		t.Fatal("same leased step failed to recover after capacity returned", state, e)
	}
}

func TestRetentionTenantIsolationAndCancellationPreserveApprovedTargets(t *testing.T) {
	db, ctx, admin, w, owner := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	a := retentionManifest(t, db, ctx, admin, "app", "isolated", 3600, nil)
	id := retentionAdmit(t, db, ctx, admin, retentionPreviewFixture(t, db, ctx, admin), "isolated-retention")
	otherToken, _ := crypt.Token()
	if e := Provision(ctx, owner.Config().ConnString(), "another-retention-team", "admin", "admin", otherToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	other, e := db.Authenticate(ctx, otherToken)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, other, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, other, Repository{Name: "retained", Format: "oci"})
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.RetentionPolicy(ctx, other, "retained", "age"); !errors.Is(e, ErrNotFound) {
		t.Fatal("policy crossed tenant", e)
	}
	if _, e = db.RetentionRun(ctx, other, id); !errors.Is(e, ErrNotFound) {
		t.Fatal("run crossed tenant", e)
	}
	if items, _, e := db.RetentionPolicies(ctx, other, "retained", "", 100); e != nil || len(items) != 0 {
		t.Fatal("policy listing crossed tenant", items, e)
	}
	if retentionCount(t, db, ctx, other, "retention_items") != 0 || retentionCount(t, db, ctx, other, "retention_observations") != 0 {
		t.Fatal("unfiltered RLS lookup crossed tenant")
	}
	j, e := db.ClaimJob(ctx, w, "maintenance", "cancel-fence", time.Minute)
	if e != nil || j.ID() != id {
		t.Fatal("claim", e)
	}
	if _, e = db.ControlJob(ctx, admin, "cancel-approved", "cancel-approved", id, "cancel", false); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, admin.CredentialHash); e != nil {
		t.Fatal(e)
	}
	if outcome, e := db.StepRetention(ctx, w, j); e != nil || outcome != "cancelled" {
		t.Fatal("cancellation needed expired original retirement authority", outcome, e)
	}
	var deleted bool
	if e = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle WHERE tenant=$1 AND path=$2 AND deleted)`, admin.Tenant, a.Path).Scan(&deleted); e != nil || deleted {
		t.Fatal("cancelled target retired", deleted, e)
	}
}
