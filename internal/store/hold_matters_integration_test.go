//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type matterFixture struct {
	db                                *Store
	ctx                               context.Context
	admin, approver                   Identity
	worker                            WorkerIdentity
	owner                             *pgx.Conn
	ownerDSN, adminToken, reviewToken string
	targets                           []MatterSelector
	roots                             []Artifact
}

func newMatterFixture(t *testing.T) matterFixture {
	t.Helper()
	d, db, owner, token, workerToken := schemaFixture(t)
	f := matterFixture{db: db, owner: owner, ctx: context.Background(), ownerDSN: d.OwnerDSN, adminToken: token}
	var e error
	f.admin, e = db.Authenticate(f.ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	f.worker, e = db.AuthenticateWorker(f.ctx, workerToken)
	if e != nil {
		t.Fatal(e)
	}
	f.reviewToken, e = crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = Provision(f.ctx, d.OwnerDSN, f.admin.Tenant, "independent-reviewer", "admin", f.reviewToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	f.approver, e = db.Authenticate(f.ctx, f.reviewToken)
	if e != nil {
		t.Fatal(e)
	}
	for n, repo := range []string{"matter-a", "matter-a", "matter-b"} {
		if n != 1 {
			if e = db.Tx(f.ctx, f.admin, true, func(tx pgx.Tx) error {
				return CreateRepository(f.ctx, tx, f.admin, Repository{Name: repo, Format: "oci"})
			}); e != nil {
				t.Fatal(e)
			}
		}
		digest := crypt.Digest([]byte(fmt.Sprintf("Owned matter reference %d", n)))
		a := Artifact{Path: "app/manifests/sha256:" + digest, Digest: digest, Size: 123, MediaType: integrationOCIImage}
		if e = publishOCIFixture(db, f.ctx, f.admin, repo, a, OCIManifestMetadata{Validated: true, References: []string{}}); e != nil {
			t.Fatal(e)
		}
		f.targets = append(f.targets, MatterSelector{Repository: repo, Path: a.Path})
		f.roots = append(f.roots, a)
	}
	return f
}

func (f matterFixture) create(t *testing.T, name string) {
	t.Helper()
	_, e := f.db.SetHoldMatter(f.ctx, f.admin, name, "create-"+name, "create-"+name, HoldMatterRequest{Title: "Owned matter " + name, State: "open", Reason: "Independent preservation investigation"})
	if e != nil {
		t.Fatal(e)
	}
}
func (f matterFixture) plan(t *testing.T, actor Identity, name, action string, targets []MatterSelector) MatterPlan {
	t.Helper()
	p, e := f.db.PreviewMatterOperation(f.ctx, actor, name, MatterPreviewRequest{Action: action, Reason: "Reviewed immutable preservation manifest", Targets: targets}, 100, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func matterResult(t *testing.T, r Result, e error) MatterOperation {
	t.Helper()
	var v struct{ Operation MatterOperation }
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(r.Body, &v) != nil || v.Operation.Sequence == 0 {
		t.Fatal(string(r.Body))
	}
	return v.Operation
}
func (f matterFixture) start(t *testing.T, actor Identity, p MatterPlan, key string) MatterOperation {
	t.Helper()
	r, e := f.db.StartMatterOperation(f.ctx, actor, p.Matter.Name, key, key, p, 100, 1<<20)
	return matterResult(t, r, e)
}
func (f matterFixture) approve(t *testing.T, o MatterOperation, key string) MatterOperation {
	t.Helper()
	r, e := f.db.ReviewMatterOperation(f.ctx, f.approver, o.Matter, o.Sequence, "approve", key, key, MatterApprovalRequest{ExpectedRevision: o.Revision, Digest: o.Plan.Digest, Reason: "Independent exact manifest release approval"})
	return matterResult(t, r, e)
}
func (f matterFixture) claim(t *testing.T, id string) Job {
	t.Helper()
	j, e := f.db.ClaimJob(f.ctx, f.worker, "maintenance", "matter-fixture", time.Minute)
	if e != nil || j.ID() != id {
		t.Fatal("claim exact matter operation", j, e)
	}
	return j
}
func (f matterFixture) drain(t *testing.T, id string) {
	t.Helper()
	for n := 0; n <= len(f.targets); n++ {
		j := f.claim(t, id)
		state, e := f.db.StepHoldMatter(f.ctx, f.worker, j)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.db.StepHoldMatter(f.ctx, f.worker, j); !errors.Is(e, ErrJobLeaseLost) {
			t.Fatal("stale worker repeated a committed effect", e)
		}
		if state == "succeeded" {
			return
		}
	}
	t.Fatal("matter did not finish")
}
func (f matterFixture) state(t *testing.T, n int) ArtifactState {
	t.Helper()
	a, e := f.db.ArtifactState(f.ctx, f.admin, f.targets[n].Repository, f.targets[n].Path)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func (f matterFixture) counts(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, table := range []string{"hold_matters", "hold_matter_members", "hold_matter_operations", "hold_matter_targets", "hold_matter_outcomes", "artifact_lifecycle", "events", "jobs", "mutations"} {
		out[table] = retentionCount(t, f.db, f.ctx, f.admin, table)
	}
	return out
}
func assertMatterCounts(t *testing.T, f matterFixture, before map[string]int) {
	t.Helper()
	for table, n := range before {
		if got := retentionCount(t, f.db, f.ctx, f.admin, table); got != n {
			t.Fatal("partial matter transaction", table, n, got)
		}
	}
}

func TestHoldMattersPreserveOverlappingLegacyCaseAndTombstoneProtection(t *testing.T) {
	f := newMatterFixture(t)
	for _, name := range []string{"alpha", "beta"} {
		f.create(t, name)
	}
	a := f.start(t, f.admin, f.plan(t, f.admin, "alpha", "hold", f.targets[:2]), "alpha-placement")
	f.drain(t, a.Job)
	b := f.start(t, f.admin, f.plan(t, f.admin, "beta", "hold", f.targets[:1]), "beta-placement")
	f.drain(t, b.Job)
	if _, e := f.db.ChangeArtifactState(f.ctx, f.admin, "matter-a", "legacy-placement", "legacy-placement", lifecycleInput(f.roots[0], "hold", f.state(t, 0).Revision), 100, nil); e != nil {
		t.Fatal(e)
	}
	caseChange(t, f.db, f.ctx, f.admin, "matter-a", "separate-case", "case-placement", caseInput(f.roots[0], "hold", 0))
	release := f.approve(t, f.start(t, f.admin, f.plan(t, f.admin, "alpha", "release_hold", f.targets[:2]), "alpha-release-request"), "alpha-release-approval")
	f.drain(t, release.Job)
	state := f.state(t, 0)
	if !state.Held || !state.MatterHeld || !state.CaseHeld || !state.LegacyHeld {
		t.Fatal("one matter release erased another authority", state)
	}
	if f.state(t, 1).Held {
		t.Fatal("released independent reference remains held")
	}
	if _, e := f.db.DeleteOCI(f.ctx, f.admin, "matter-a", "app", "manifests", "sha256:"+f.roots[0].Digest, 100); !errors.Is(e, ErrHeld) {
		t.Fatal(e)
	}
	other := f.approve(t, f.start(t, f.admin, f.plan(t, f.admin, "beta", "release_hold", f.targets[:1]), "beta-release-request"), "beta-release-approval")
	f.drain(t, other.Job)
	state = f.state(t, 0)
	if state.MatterHeld || !state.CaseHeld || !state.LegacyHeld {
		t.Fatal(state)
	}
	if _, e := f.db.DeleteOCI(f.ctx, f.admin, "matter-a", "app", "manifests", "sha256:"+f.roots[1].Digest, 100); e != nil {
		t.Fatal(e)
	}
	newHold := f.start(t, f.admin, f.plan(t, f.admin, "alpha", "hold", f.targets[1:2]), "tombstone-placement")
	f.drain(t, newHold.Job)
	state = f.state(t, 1)
	if !state.Held || !state.Deleted {
		t.Fatal(state)
	}
	if _, e := f.db.RestorationGraph(f.ctx, f.admin, "matter-a", lifecycleInput(f.roots[1], "restore", state.Revision)); !errors.Is(e, ErrHeld) {
		t.Fatal("matter did not fence restore", e)
	}
	if _, e := f.db.SetHoldMatter(f.ctx, f.admin, "alpha", "close-held-matter", "close-held-matter", HoldMatterRequest{ExpectedRevision: 1, State: "closed", Title: "Closed", Reason: "Attempt closure while held"}); !errors.Is(e, ErrMatterChanged) {
		t.Fatal("closed an unreleased matter", e)
	}
}

func TestHoldMatterExactManifestAdmissionAndCurrentRevision(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "review")
	p := f.plan(t, f.admin, "review", "hold", f.targets)
	before := f.counts(t)
	for n, alter := range []func(*MatterPlan){
		func(p *MatterPlan) { p.Targets[0].Digest = crypt.Digest([]byte("substituted")) },
		func(p *MatterPlan) { p.Targets[0].Status = "released" },
		func(p *MatterPlan) { p.Targets[0].EffectiveHeld = true },
		func(p *MatterPlan) { p.Targets[0].LifecycleRevision++ },
		func(p *MatterPlan) { p.Targets[0].Revision++ },
		func(p *MatterPlan) { slices.Reverse(p.Targets) },
		func(p *MatterPlan) { p.Reason = "Unreviewed replacement reason" },
		func(p *MatterPlan) { p.Requester = "somebody-else" },
		func(p *MatterPlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Hour) },
		func(p *MatterPlan) { p.Digest = crypt.Digest([]byte("forged")) },
	} {
		raw, _ := json.Marshal(p)
		var changed MatterPlan
		if e := json.Unmarshal(raw, &changed); e != nil {
			t.Fatal(e)
		}
		alter(&changed)
		key := fmt.Sprintf("substitution-%d", n)
		if _, e := f.db.StartMatterOperation(f.ctx, f.admin, "review", key, key, changed, 100, 1<<20); !errors.Is(e, ErrMatterChanged) {
			t.Fatal(n, "altered reviewed manifest admitted", e)
		}
		assertMatterCounts(t, f, before)
	}
	if _, e := f.db.PreviewMatterOperation(f.ctx, f.admin, "review", MatterPreviewRequest{Action: "hold", Reason: p.Reason, Targets: []MatterSelector{f.targets[0], f.targets[0]}}, 100, 1<<20); !errors.Is(e, ErrMatterInput) {
		t.Fatal("duplicate selectors admitted", e)
	}
	if _, e := f.db.PreviewMatterOperation(f.ctx, f.admin, "review", MatterPreviewRequest{Action: "hold", Reason: p.Reason, Targets: f.targets}, 2, 1<<20); !errors.Is(e, ErrMatterInput) {
		t.Fatal("target cap produced a truncated preview", e)
	}
	if _, e := f.db.SetHoldMatter(f.ctx, f.admin, "review", "edit-matter", "edit-matter", HoldMatterRequest{ExpectedRevision: 1, Title: "Changed investigation", State: "open", Reason: "Metadata review supersedes earlier preview"}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.StartMatterOperation(f.ctx, f.admin, "review", "stale-metadata", "stale-metadata", p, 100, 1<<20); !errors.Is(e, ErrMatterChanged) {
		t.Fatal("stale matter metadata admitted", e)
	}
	p = f.plan(t, f.admin, "review", "hold", f.targets)
	placed := f.start(t, f.admin, f.plan(t, f.admin, "review", "hold", f.targets[:1]), "independent-placement")
	f.drain(t, placed.Job)
	if _, e := f.db.StartMatterOperation(f.ctx, f.admin, "review", "stale-member", "stale-member", p, 100, 1<<20); !errors.Is(e, ErrMatterChanged) {
		t.Fatal("stale member revision admitted", e)
	}
}

func TestHoldMatterCompletePreviewIncludesDigestInByteBudget(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "budget")
	p := f.plan(t, f.admin, "budget", "hold", f.targets)
	raw, _ := json.Marshal(p)
	if len(raw) <= 1024 {
		t.Fatal("fixture must exercise full manifest budget")
	}
	var e error
	if e = f.db.Tx(f.ctx, f.admin, false, func(tx pgx.Tx) error {
		_, e := matterPreview(f.ctx, tx, f.admin, "budget", MatterPreviewRequest{Action: "hold", Reason: p.Reason, Targets: f.targets}, &p.EvaluatedAt, 100, len(raw)-1)
		return e
	}); !errors.Is(e, ErrMatterBudget) {
		t.Fatal("complete preview exceeded its byte budget", e)
	}
}

func (f matterFixture) capacity(t *testing.T, queue string, n int) {
	t.Helper()
	if e := f.db.Tx(f.ctx, f.admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO cratectl.queue_policies(tenant,queue,capacity) VALUES($1,$2,$3) ON CONFLICT(tenant,queue) DO UPDATE SET capacity=excluded.capacity`, f.admin.Tenant, queue, n)
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestHoldMatterAdmissionApprovalAndTargetQueueRollback(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "atomic")
	p := f.plan(t, f.admin, "atomic", "hold", f.targets)
	f.capacity(t, "events", 1)
	before := f.counts(t)
	if _, e := f.db.StartMatterOperation(f.ctx, f.admin, "atomic", "atomic-request", "atomic-request", p, 100, 1<<20); !errors.Is(e, ErrQueueFull) {
		t.Fatal("request ignored event queue saturation", e)
	}
	assertMatterCounts(t, f, before)
	f.capacity(t, "events", 100000)
	o := f.start(t, f.admin, p, "atomic-request")
	first, e := f.db.StartMatterOperation(f.ctx, f.admin, "atomic", "atomic-request", "atomic-request", p, 100, 1<<20)
	if e != nil || !first.Replay {
		t.Fatal("lost admission response did not replay", e)
	}
	j := f.claim(t, o.Job)
	f.capacity(t, "events", 1)
	before = f.counts(t)
	if _, e = f.db.StepHoldMatter(f.ctx, f.worker, j); !errors.Is(e, ErrQueueFull) {
		t.Fatal("target effect ignored projection saturation", e)
	}
	assertMatterCounts(t, f, before)
	for n := range f.roots {
		if f.state(t, n).Held {
			t.Fatal("rolled-back effect retained a hold")
		}
	}
	f.capacity(t, "events", 100000)
	if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "pending" {
		t.Fatal(state, e)
	}
	f.drain(t, o.Job)
	release := f.start(t, f.admin, f.plan(t, f.admin, "atomic", "release_hold", f.targets), "atomic-release")
	// A separate placement occupies the maintenance queue while review is pending.
	f.create(t, "queue-blocker")
	blocker := f.start(t, f.admin, f.plan(t, f.admin, "queue-blocker", "hold", f.targets[:1]), "queue-blocker-placement")
	f.capacity(t, "maintenance", 1)
	request := MatterApprovalRequest{ExpectedRevision: release.Revision, Digest: release.Plan.Digest, Reason: "Exact independently reviewed release"}
	before = f.counts(t)
	if _, e := f.db.ReviewMatterOperation(f.ctx, f.approver, "atomic", release.Sequence, "approve", "atomic-approve", "atomic-approve", request); !errors.Is(e, ErrQueueFull) {
		t.Fatal("approval ignored maintenance saturation", e)
	}
	assertMatterCounts(t, f, before)
	current, e := f.db.MatterOperation(f.ctx, f.admin, "atomic", release.Sequence)
	if e != nil || current["operation"].(MatterOperation).State != "awaiting_approval" {
		t.Fatal(current, e)
	}
	f.drain(t, blocker.Job)
	approved := f.approve(t, release, "atomic-approve")
	replay, e := f.db.ReviewMatterOperation(f.ctx, f.approver, "atomic", release.Sequence, "approve", "atomic-approve", "atomic-approve", request)
	if e != nil || !replay.Replay {
		t.Fatal("lost approval response did not replay", e)
	}
	f.drain(t, approved.Job)
	if !f.state(t, 0).MatterHeld || f.state(t, 1).Held || f.state(t, 2).Held {
		t.Fatal("release crossed independent matter boundary")
	}
}

func TestHoldMatterPartialCancelRetryImmutablePayloadAndNewMembership(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "partial")
	o := f.start(t, f.admin, f.plan(t, f.admin, "partial", "hold", f.targets[:2]), "partial-placement")
	j := f.claim(t, o.Job)
	// Job progress is mutable; it must never replace the admitted target manifest.
	if e := f.db.Tx(f.ctx, f.admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE cratectl.jobs SET payload=$1 WHERE sequence=$2 AND task=$3`, []byte(`{"matter":"other","operation":999,"targets":0,"requester":"other"}`), j.Sequence, j.Task)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "pending" {
		t.Fatal(state, e)
	}
	if _, e := f.db.ControlJob(f.ctx, f.admin, "cancel-partial", "cancel-partial", o.Job, "cancel", false); e != nil {
		t.Fatal(e)
	}
	if retentionCount(t, f.db, f.ctx, f.admin, "hold_matter_outcomes") != 1 {
		t.Fatal("cancel erased or invented completed work")
	}
	if _, e := f.db.ControlJob(f.ctx, f.admin, "retry-partial", "retry-partial", o.Job, "retry", false); e != nil {
		t.Fatal(e)
	}
	f.drain(t, o.Job)
	if retentionCount(t, f.db, f.ctx, f.admin, "hold_matter_outcomes") != 2 {
		t.Fatal("retry duplicated outcomes")
	}
	for n := 0; n < 2; n++ {
		if f.state(t, n).Revision != 1 {
			t.Fatal("retry reapplied an observed target", n, f.state(t, n))
		}
	}
	release := f.start(t, f.admin, f.plan(t, f.admin, "partial", "release_hold", f.targets[:2]), "partial-release")
	// The later member was absent from the reviewed release and must stay held.
	late := f.start(t, f.admin, f.plan(t, f.admin, "partial", "hold", f.targets[2:]), "late-member-placement")
	f.drain(t, late.Job)
	approved := f.approve(t, release, "partial-release-approval")
	j = f.claim(t, approved.Job)
	if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "pending" {
		t.Fatal(state, e)
	}
	j = f.claim(t, approved.Job)
	if _, e := f.db.ControlJob(f.ctx, f.admin, "cancel-running-release", "cancel-running-release", approved.Job, "cancel", false); e != nil {
		t.Fatal(e)
	}
	before := retentionCount(t, f.db, f.ctx, f.admin, "hold_matter_outcomes")
	if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "cancelled" {
		t.Fatal(state, e)
	}
	if retentionCount(t, f.db, f.ctx, f.admin, "hold_matter_outcomes") != before {
		t.Fatal("cancel-requested job released another target")
	}
	if _, e := f.db.ControlJob(f.ctx, f.admin, "retry-release", "retry-release", approved.Job, "retry", false); e != nil {
		t.Fatal(e)
	}
	f.drain(t, approved.Job)
	if f.state(t, 0).Held || f.state(t, 1).Held || !f.state(t, 2).Held {
		t.Fatal("release included membership outside the approved manifest")
	}
	rows, _, e := f.db.MatterOperationItems(f.ctx, f.admin, "partial", release.Sequence, ListRequest{Limit: 10})
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	for _, row := range rows {
		if row.Outcome != "released" || row.MemberRevision != 2 {
			t.Fatal("partial retry repeated release", row)
		}
	}
}

func TestHoldMatterRevokedAuthoritiesCannotContinueOrTransferApproval(t *testing.T) {
	for _, revoked := range []string{"requester", "approver"} {
		t.Run(revoked, func(t *testing.T) {
			f := newMatterFixture(t)
			f.create(t, "revocation")
			o := f.start(t, f.admin, f.plan(t, f.admin, "revocation", "hold", f.targets), "revocation-placement")
			f.drain(t, o.Job)
			release := f.start(t, f.admin, f.plan(t, f.admin, "revocation", "release_hold", f.targets), "revocation-release")
			approved := f.approve(t, release, "revocation-approval")
			j := f.claim(t, approved.Job)
			if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "pending" {
				t.Fatal(state, e)
			}
			token := f.adminToken
			if revoked == "approver" {
				token = f.reviewToken
			}
			if e := Revoke(f.ctx, f.ownerDSN, token); e != nil {
				t.Fatal(e)
			}
			oldRequester := f.admin
			recoveryToken, e := crypt.Token()
			if e != nil {
				t.Fatal(e)
			}
			if e = Provision(f.ctx, f.ownerDSN, f.admin.Tenant, "recovery-administrator", "admin", recoveryToken, time.Now().Add(time.Hour)); e != nil {
				t.Fatal(e)
			}
			f.admin, e = f.db.Authenticate(f.ctx, recoveryToken)
			if e != nil {
				t.Fatal(e)
			}
			if revoked == "approver" {
				f.approver = oldRequester
			}
			j = f.claim(t, approved.Job)
			before := f.counts(t)
			if _, e = f.db.StepHoldMatter(f.ctx, f.worker, j); !errors.Is(e, ErrMatterAuthorization) {
				t.Fatal("revoked authority released another reference", e)
			}
			assertMatterCounts(t, f, before)
			if state, e := f.db.FailJob(f.ctx, f.worker, j, "hold_matter_authorization", true); e != nil || state != "failed" {
				t.Fatal(state, e)
			}
			if _, e = f.db.ControlJob(f.ctx, f.admin, "retry-revoked-intent", "retry-revoked-intent", approved.Job, "retry", false); e != nil {
				t.Fatal(e)
			}
			j = f.claim(t, approved.Job)
			if _, e = f.db.StepHoldMatter(f.ctx, f.worker, j); !errors.Is(e, ErrMatterAuthorization) {
				t.Fatal("job retry substituted the recovery administrator", e)
			}
			if _, e = f.db.ControlJob(f.ctx, f.admin, "cancel-revoked-intent", "cancel-revoked-intent", approved.Job, "cancel", false); e != nil {
				t.Fatal(e)
			}
			if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "cancelled" {
				t.Fatal(state, e)
			}
			// Recovery requires a fresh current requester, manifest and independent review.
			items, _, e := f.db.MatterOperationItems(f.ctx, f.admin, "revocation", release.Sequence, ListRequest{Limit: 10})
			if e != nil || len(items) != 3 {
				t.Fatal(items, e)
			}
			remaining := []MatterSelector{}
			for _, item := range items {
				if item.Outcome == "pending" {
					remaining = append(remaining, MatterSelector{Repository: item.Repository, Path: item.Path})
				}
			}
			if len(remaining) != 2 {
				t.Fatal("committed partial result changed", items)
			}
			fresh := f.start(t, f.admin, f.plan(t, f.admin, "revocation", "release_hold", remaining), "recovery-release")
			fresh = f.approve(t, fresh, "recovery-approval")
			f.drain(t, fresh.Job)
			for n := range f.roots {
				if f.state(t, n).Held {
					t.Fatal("fresh current recovery did not complete", n)
				}
			}
		})
	}
}

func TestHoldMatterIndependentCurrentApprovalAndTenantBoundaries(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "approval")
	placement := f.start(t, f.admin, f.plan(t, f.admin, "approval", "hold", f.targets), "approval-placement")
	f.drain(t, placement.Job)
	releasePlan := f.plan(t, f.admin, "approval", "release_hold", f.targets)
	release := f.start(t, f.admin, releasePlan, "approval-release")
	request := MatterApprovalRequest{ExpectedRevision: release.Revision, Digest: release.Plan.Digest, Reason: "Reviewed exact release manifest"}
	secondToken, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = Provision(f.ctx, f.ownerDSN, f.admin.Tenant, f.admin.Actor, "admin", secondToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	sameActor, e := f.db.Authenticate(f.ctx, secondToken)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.ReviewMatterOperation(f.ctx, sameActor, "approval", release.Sequence, "approve", "same-actor-approval", "same-actor-approval", request); !errors.Is(e, ErrDenied) {
		t.Fatal("second credential bypassed separation of duties", e)
	}
	for _, role := range []string{"writer", "reader", "worker"} {
		other := f.admin
		other.Role = role
		other.CredentialHash = ""
		if _, e = f.db.ReviewMatterOperation(f.ctx, other, "approval", release.Sequence, "approve", "role-approval", "role-approval", request); !errors.Is(e, ErrDenied) {
			t.Fatal(role, e)
		}
		if _, _, _, e = f.db.MatterMembers(f.ctx, other, "approval", MatterMemberPageRequest{ListRequest: ListRequest{Limit: 10}}); !errors.Is(e, ErrDenied) {
			t.Fatal(role, "read members", e)
		}
	}
	other := Identity{Tenant: "another-tenant", Actor: "other-admin", Role: "admin"}
	if _, e = f.db.MatterOperation(f.ctx, other, "approval", release.Sequence); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant proposal visible", e)
	}
	if e = Revoke(f.ctx, f.ownerDSN, f.adminToken); e != nil {
		t.Fatal(e)
	}
	before := retentionCount(t, f.db, f.ctx, f.approver, "jobs")
	if _, e = f.db.ReviewMatterOperation(f.ctx, f.approver, "approval", release.Sequence, "approve", "revoked-before-approval", "revoked-before-approval", request); !errors.Is(e, ErrMatterAuthorization) {
		t.Fatal("revoked requester approved", e)
	}
	if retentionCount(t, f.db, f.ctx, f.approver, "jobs") != before {
		t.Fatal("revoked request enqueued work")
	}
	// A current administrator can cancel the stranded proposal without taking it over.
	r, e := f.db.ReviewMatterOperation(f.ctx, f.approver, "approval", release.Sequence, "cancel", "cancel-stranded-proposal", "cancel-stranded-proposal", request)
	if o := matterResult(t, r, e); o.State != "cancelled" || o.Job != "" {
		t.Fatal(o)
	}
	if _, e = f.db.StartMatterOperation(f.ctx, f.admin, "approval", "approval-release", "approval-release", releasePlan, 100, 1<<20); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("revoked requester replayed response", e)
	}
}

func TestHoldMatterLeaseFencesAndChangedTargetOutcome(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "fences")
	o := f.start(t, f.admin, f.plan(t, f.admin, "fences", "hold", f.targets), "fenced-placement")
	old := f.claim(t, o.Job)
	if e := f.db.Tx(f.ctx, f.admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE cratectl.jobs SET lease_until='epoch' WHERE sequence=$1 AND task=$2`, old.Sequence, old.Task)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	newer := f.claim(t, o.Job)
	if newer.Generation <= old.Generation {
		t.Fatal("expired lease reused generation")
	}
	before := f.counts(t)
	if _, e := f.db.StepHoldMatter(f.ctx, f.worker, old); !errors.Is(e, ErrJobLeaseLost) {
		t.Fatal("stale generation changed hold", e)
	}
	assertMatterCounts(t, f, before)
	if state, e := f.db.StepHoldMatter(f.ctx, f.worker, newer); e != nil || state != "pending" {
		t.Fatal(state, e)
	}
	f.drain(t, o.Job)
	release := f.start(t, f.admin, f.plan(t, f.admin, "fences", "release_hold", f.targets), "changed-target-release")
	// A newly reviewed hold refreshes one binding after release admission.
	refresh := f.start(t, f.admin, f.plan(t, f.admin, "fences", "hold", f.targets[:1]), "refresh-one-binding")
	f.drain(t, refresh.Job)
	approved := f.approve(t, release, "changed-target-approval")
	f.drain(t, approved.Job)
	items, _, e := f.db.MatterOperationItems(f.ctx, f.admin, "fences", release.Sequence, ListRequest{Limit: 10})
	if e != nil || len(items) != 3 {
		t.Fatal(items, e)
	}
	changed := 0
	for _, item := range items {
		if item.Path == f.targets[0].Path {
			if item.Outcome != "changed" || item.MemberRevision != 2 || item.EffectiveHeldAfter == nil || !*item.EffectiveHeldAfter {
				t.Fatal("stale release erased refreshed hold", item)
			}
			changed++
		} else if item.Outcome != "released" {
			t.Fatal(item)
		}
	}
	if changed != 1 || !f.state(t, 0).Held || f.state(t, 1).Held || f.state(t, 2).Held {
		t.Fatal("changed target lost partial outcome")
	}
	detail, e := f.db.MatterOperation(f.ctx, f.admin, "fences", release.Sequence)
	if e != nil || detail["processed"] != int64(3) || detail["effected"] != int64(2) || detail["skipped"] != int64(1) {
		t.Fatal(detail, e)
	}
}

func matterSQLCode(e error) string {
	var state interface{ SQLState() string }
	if errors.As(e, &state) {
		return state.SQLState()
	}
	return ""
}
func TestHoldMatterRLSAndImmutableAdmissionRecords(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "immutable")
	o := f.start(t, f.admin, f.plan(t, f.admin, "immutable", "hold", f.targets[:1]), "immutable-placement")
	f.drain(t, o.Job)
	var safe bool
	if e := f.db.Pool.QueryRow(f.ctx, `SELECT NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&safe); e != nil || !safe {
		t.Fatal("runtime bypasses RLS", safe, e)
	}
	for _, table := range []string{"hold_matters", "hold_matter_members", "hold_matter_operations", "hold_matter_targets", "hold_matter_outcomes"} {
		var count int
		if e := f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&count); e != nil || count != 0 {
			t.Fatal("unset-tenant RLS", table, count, e)
		}
		if e := f.db.Pool.QueryRow(f.ctx, `SELECT relrowsecurity AND relforcerowsecurity AND pg_get_userbyid(relowner)<>current_user FROM pg_class WHERE oid=$1::regclass`, "cratectl."+table).Scan(&safe); e != nil || !safe {
			t.Fatal("unsafe tenant table", table, e)
		}
		if e := f.db.Tx(f.ctx, Identity{Tenant: "other", Actor: "other-admin", Role: "admin"}, false, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&count) }); e != nil || count != 0 {
			t.Fatal("cross-tenant RLS", table, count, e)
		}
	}
	for _, sql := range []string{
		`UPDATE cratectl.hold_matter_operations SET plan='{}'`,
		`UPDATE cratectl.hold_matter_operations SET requester_hash='replacement'`,
		`UPDATE cratectl.hold_matter_operations SET expires_at=clock_timestamp()+interval '1 hour'`,
		`UPDATE cratectl.hold_matter_targets SET target='{}'`,
		`UPDATE cratectl.hold_matter_outcomes SET outcome='released'`,
		`UPDATE cratectl.hold_matter_members SET digest=repeat('f',64)`,
		`UPDATE cratectl.hold_matter_members SET created_sequence=999999`,
		`UPDATE cratectl.hold_matters SET name='replacement'`,
		`DELETE FROM cratectl.hold_matter_outcomes`,
	} {
		e := f.db.Tx(f.ctx, f.admin, true, func(tx pgx.Tx) error { _, e := tx.Exec(f.ctx, sql); return e })
		if matterSQLCode(e) != "42501" {
			t.Fatal("runtime could rewrite immutable admission or observation", sql, e)
		}
	}
	if e := f.db.Tx(f.ctx, f.admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO cratectl.hold_matters(tenant,name,revision,state,title,reason,actor,created_sequence,change_sequence) VALUES('other','cross-tenant',1,'open','Cross-tenant','Forbidden','other',1,1)`)
		return e
	}); matterSQLCode(e) != "42501" {
		t.Fatal("cross-tenant insertion bypassed RLS", e)
	}
	events, _, e := f.db.MatterHistory(f.ctx, f.admin, "immutable", ListRequest{Limit: 10})
	if e != nil || len(events) != 3 {
		t.Fatal(events, e)
	}
	for _, event := range events {
		for _, private := range []string{f.adminToken, f.reviewToken, f.admin.CredentialHash, f.approver.CredentialHash} {
			if strings.Contains(string(event.Data), private) {
				t.Fatal("private authority appeared in journal")
			}
		}
	}
}

func TestHoldMattersUpgradePreservesTenReceiptsAndJournal(t *testing.T) {
	testHoldUpgradePreservesReceiptsAndJournal(t, 10)
}

func TestHoldMatterRealExpiryPreservesReceiptAndStopsLateEffects(t *testing.T) {
	f := newMatterFixture(t)
	f.create(t, "timed")
	f.create(t, "ongoing")
	until := time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Second)
	p, e := f.db.PreviewMatterOperation(f.ctx, f.admin, "timed", MatterPreviewRequest{Action: "hold", Reason: "Owned real expiry review", HoldUntil: &until, Targets: f.targets}, 100, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	o := f.start(t, f.admin, p, "timed-placement")
	j := f.claim(t, o.Job)
	if state, e := f.db.StepHoldMatter(f.ctx, f.worker, j); e != nil || state != "pending" {
		t.Fatal(state, e)
	}
	items, _, e := f.db.MatterOperationItems(f.ctx, f.admin, "timed", o.Sequence, ListRequest{Limit: 10})
	if e != nil {
		t.Fatal(e)
	}
	var placed MatterSelector
	for _, item := range items {
		if item.Outcome == "held" {
			placed = MatterSelector{Repository: item.Repository, Path: item.Path}
		}
	}
	if placed.Path == "" {
		t.Fatal("first timed target was not committed")
	}
	// Pause the partial timed job so another matter can preserve its observed target.
	if _, e = f.db.ControlJob(f.ctx, f.admin, "pause-timed", "pause-timed", o.Job, "cancel", false); e != nil {
		t.Fatal(e)
	}
	other := f.start(t, f.admin, f.plan(t, f.admin, "ongoing", "hold", []MatterSelector{placed}), "ongoing-placement")
	f.drain(t, other.Job)
	time.Sleep(time.Until(until) + 20*time.Millisecond)
	rows, _, observed, e := f.db.MatterMembers(f.ctx, f.admin, "timed", MatterMemberPageRequest{ListRequest: ListRequest{Limit: 10}, State: "expired"})
	if e != nil || len(rows) != 1 || rows[0].Held || rows[0].Released || observed.Before(until) {
		t.Fatal(rows, observed, e)
	}
	if _, e = f.db.DeleteOCI(f.ctx, f.admin, placed.Repository, "app", "manifests", "sha256:"+rows[0].Digest, 100); !errors.Is(e, ErrHeld) {
		t.Fatal("expired matter erased ongoing protection", e)
	}
	history, _, e := f.db.MatterHistory(f.ctx, f.admin, "timed", ListRequest{Limit: 10})
	if e != nil || len(history) != 3 {
		t.Fatal(history, e)
	}
	var snapshot struct{ Member HoldMatterMember }
	if e = json.Unmarshal(history[2].Data, &snapshot); e != nil || !snapshot.Member.Held {
		t.Fatal("expiry rewrote original preservation receipt", e)
	}
	if _, e = f.db.ControlJob(f.ctx, f.admin, "retry-expired", "retry-expired", o.Job, "retry", false); e != nil {
		t.Fatal(e)
	}
	j = f.claim(t, o.Job)
	before := f.counts(t)
	if _, e = f.db.StepHoldMatter(f.ctx, f.worker, j); !errors.Is(e, ErrMatterChanged) {
		t.Fatal("expired placement continued to new targets", e)
	}
	assertMatterCounts(t, f, before)
}

func TestHoldMatterFirstOversizedRecordsFailInsteadOfTruncating(t *testing.T) {
	f := newMatterFixture(t)
	_, e := f.db.SetHoldMatter(f.ctx, f.admin, "large", "create-large", "create-large", HoldMatterRequest{Title: strings.Repeat("T", 256), Reason: strings.Repeat("R", 1024), State: "open"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.db.MatterPage(f.ctx, f.admin, ListRequest{Limit: 10, MetadataBytes: 1024}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized first matter record", e)
	}
	p, e := f.db.PreviewMatterOperation(f.ctx, f.admin, "large", MatterPreviewRequest{Action: "hold", Reason: strings.Repeat("P", 1024), Targets: f.targets[:1]}, 100, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	o := f.start(t, f.admin, p, "large-placement")
	f.drain(t, o.Job)
	if _, _, _, e = f.db.MatterMembers(f.ctx, f.admin, "large", MatterMemberPageRequest{ListRequest: ListRequest{Limit: 10, MetadataBytes: 1024}, State: "all"}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized first member record", e)
	}
	if _, _, e = f.db.MatterOperations(f.ctx, f.admin, "large", ListRequest{Limit: 10, MetadataBytes: 1024}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized first operation summary", e)
	}
	if _, _, e = f.db.MatterHistory(f.ctx, f.admin, "large", ListRequest{Limit: 10, MetadataBytes: 1024}); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("oversized original history record", e)
	}
}

func TestHoldMatterAddedAfterRetirementAdmissionProtectsCapturedReference(t *testing.T) {
	db, ctx, admin, worker, _ := retentionFixture(t)
	retentionConfigure(t, db, ctx, admin, retentionPolicyInput())
	root := retentionManifest(t, db, ctx, admin, "late-matter", "late-matter-reference", 3600, nil)
	retirement := retentionAdmit(t, db, ctx, admin, retentionPreviewFixture(t, db, ctx, admin), "capture-before-matter")
	lease, e := db.ClaimJob(ctx, worker, "maintenance", "retirement-before-matter", time.Minute)
	if e != nil || lease.ID() != retirement {
		t.Fatal(lease, e)
	}
	f := matterFixture{db: db, ctx: ctx, admin: admin, worker: worker, targets: []MatterSelector{{Repository: "retained", Path: root.Path}}, roots: []Artifact{root}}
	f.create(t, "late-protection")
	hold := f.start(t, admin, f.plan(t, admin, "late-protection", "hold", f.targets), "place-late-matter")
	f.drain(t, hold.Job)
	if state, e := db.StepRetention(ctx, worker, lease); e != nil || state != "succeeded" {
		t.Fatal(state, e)
	}
	rows, _, e := db.RetentionItems(ctx, admin, retirement, 0, 10)
	if e != nil || len(rows) != 1 || rows[0].Outcome != "held" {
		t.Fatal("captured retirement bypassed later matter protection", rows, e)
	}
	current := f.state(t, 0)
	if !current.Held || !current.MatterHeld || current.Deleted {
		t.Fatal("retirement changed protected reference", current)
	}
}
