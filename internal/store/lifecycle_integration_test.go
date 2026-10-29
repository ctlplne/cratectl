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

	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func lifecycleFixture(t *testing.T) (*Store, context.Context, Identity, string, Artifact, Artifact) {
	t.Helper()
	_, db, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	repo := "lifecycle"
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, Repository{Name: repo, Format: "oci"}) }); e != nil {
		t.Fatal(e)
	}
	child := Artifact{Path: "app/blobs/sha256:" + strings.Repeat("1", 64), Digest: strings.Repeat("1", 64), Size: 42, MediaType: "application/octet-stream"}
	root := Artifact{Path: "app/manifests/sha256:" + strings.Repeat("2", 64), Digest: strings.Repeat("2", 64), Size: 123, MediaType: integrationOCIImage}
	m := OCIManifestMetadata{Validated: true, References: []string{child.Path}, Descriptors: map[string]OCIDescriptor{child.Path: {"text/plain", "sha256:" + child.Digest, child.Size}}}
	if e = db.Publish(ctx, i, repo, []Artifact{child}); e != nil {
		t.Fatal(e)
	}
	if e = publishOCIFixture(db, ctx, i, repo, root, m); e != nil {
		t.Fatal(e)
	}
	return db, ctx, i, repo, child, root
}
func lifecycleInput(a Artifact, action string, rev int64) ArtifactStateRequest {
	return ArtifactStateRequest{Path: a.Path, Digest: a.Digest, Action: action, ExpectedRevision: rev, Reason: "owned lifecycle verification"}
}

func TestLifecycleLegacyManifestNeedsIntakeRepairBeforeDeletion(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	if e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata='{}'::jsonb WHERE repository=$1 AND path=$2`, repo, root.Path)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 10); !errors.Is(e, ErrOCIUnvalidated) {
		t.Fatal("unvalidated legacy manifest became an unrecoverable tombstone", e)
	}
	state, e := db.ArtifactState(ctx, i, repo, root.Path)
	if e != nil || state.Deleted || state.Revision != 0 {
		t.Fatal(state, e)
	}
}

func TestLifecycleReferencesTombstonesAndVerifiedRestore(t *testing.T) {
	db, ctx, i, repo, child, root := lifecycleFixture(t)
	if _, e := db.DeleteOCI(ctx, i, repo, "app", "blobs", "sha256:"+child.Digest, 10); !errors.Is(e, ErrReferenced) {
		t.Fatal("deleted referenced blob", e)
	}
	preview := lifecycleInput(root, "delete", 0)
	preview.DryRun = true
	result, e := db.ChangeArtifactState(ctx, i, repo, "", "", preview, 10, nil)
	if e != nil {
		t.Fatal(e)
	}
	var p ArtifactStatePreview
	if json.Unmarshal(result.Body, &p) != nil || len(p.Tags) != 1 || p.Current.Deleted {
		t.Fatal(string(result.Body))
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 10); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Artifact(ctx, i, repo, root.Path); !errors.Is(e, ErrDeleted) {
		t.Fatal(e)
	}
	if _, e = db.OCIManifest(ctx, i, repo, "app", "latest"); !errors.Is(e, ErrDeleted) {
		t.Fatal("deleted tag target", e)
	}
	tags, _, e := db.OCIDiscovery(ctx, i, repo, "app", "tags/list", "", "", 10, 1<<20)
	if e != nil || len(tags) != 0 {
		t.Fatal(tags, e)
	}
	var m OCIManifestMetadata
	if e = db.Tx(ctx, i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT metadata FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, root.Path).Scan(&m)
	}); e != nil {
		t.Fatal(e)
	}
	if e = publishOCIFixture(db, ctx, i, repo, root, m); !errors.Is(e, ErrDeleted) {
		t.Fatal("republish restored tombstone", e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "blobs", "sha256:"+child.Digest, 10); e != nil {
		t.Fatal(e)
	}
	if _, e = db.RestorationGraph(ctx, i, repo, lifecycleInput(root, "restore", 1)); !errors.Is(e, ErrDeleted) {
		t.Fatal("restored with deleted child", e)
	}
	for _, a := range []Artifact{child, root} {
		input := lifecycleInput(a, "restore", 1)
		proof, e := db.RestorationGraph(ctx, i, repo, input)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ChangeArtifactState(ctx, i, repo, "", "", input, 10, nil); !errors.Is(e, ErrLifecycleRevision) {
			t.Fatal("accepted absent proof", e)
		}
		if _, e = db.ChangeArtifactState(ctx, i, repo, "", "", input, 10, proof); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.OCIManifest(ctx, i, repo, "app", "latest"); e != nil {
		t.Fatal("restore lost retained tag", e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := Decide(ctx, tx, i, repo, root.Path, root.Digest, "denied"); return e }); e != nil {
		t.Fatal(e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 10); e != nil {
		t.Fatal(e)
	}
	input := lifecycleInput(root, "restore", 3)
	proof, e := db.RestorationGraph(ctx, i, repo, input)
	if e != nil {
		t.Fatal("denial blocked recovery metadata", e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "", "", input, 10, proof); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Artifact(ctx, i, repo, root.Path); !errors.Is(e, ErrDenied) {
		t.Fatal("restore cleared security decision", e)
	}
}

func TestLifecycleHoldsRevisionsIdempotencyAndIsolation(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	hold := lifecycleInput(root, "hold", 0)
	first, e := db.ChangeArtifactState(ctx, i, repo, "hold-operation", "hold-fingerprint", hold, 10, nil)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := db.ChangeArtifactState(ctx, i, repo, "hold-operation", "hold-fingerprint", hold, 10, nil)
	if e != nil || !replay.Replay || string(first.Body) != string(replay.Body) {
		t.Fatal("hold replay", e)
	}
	demoted := Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "writer"}
	if _, e = db.ChangeArtifactState(ctx, demoted, repo, "hold-operation", "hold-fingerprint", hold, 10, nil); !errors.Is(e, ErrDenied) {
		t.Fatal("demoted actor replayed administrator hold", e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 10); !errors.Is(e, ErrHeld) {
		t.Fatal(e)
	}
	if _, e = db.DeleteOCI(ctx, i, repo, "app", "manifests", "latest", 10); !errors.Is(e, ErrHeld) {
		t.Fatal("tag bypassed hold", e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "", "", lifecycleInput(root, "release_hold", 0), 10, nil); !errors.Is(e, ErrLifecycleRevision) {
		t.Fatal(e)
	}
	writer := Identity{Tenant: i.Tenant, Actor: "writer", Role: "writer"}
	if _, e = db.ChangeArtifactState(ctx, writer, repo, "", "", lifecycleInput(root, "release_hold", 1), 10, nil); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "", "", lifecycleInput(root, "release_hold", 1), 10, nil); e != nil {
		t.Fatal(e)
	}
	other := Identity{Tenant: "other-lifecycle", Actor: "operator", Role: "admin"}
	if _, e = db.ArtifactState(ctx, other, repo, root.Path); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant state leak", e)
	}
	reader := Identity{Tenant: i.Tenant, Actor: "reader", Role: "reader"}
	if _, e = db.ChangeArtifactState(ctx, reader, repo, "", "", lifecycleInput(root, "delete", 2), 10, nil); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	if _, e = db.ChangeArtifactState(ctx, i, repo, "", "", lifecycleInput(root, "delete", 2), 10, nil); e != nil {
		t.Fatal(e)
	}
	alias := root
	alias.Path = "other/manifests/sha256:" + root.Digest
	if e = db.Publish(ctx, i, repo, []Artifact{alias}); e != nil {
		t.Fatal("same bytes at another path blocked", e)
	}
	if e = db.CheckOCIDigestDecision(ctx, i, repo, "sha256:"+root.Digest, alias.Path); e != nil {
		t.Fatal("tombstone became digest denial", e)
	}
	if e = db.CheckOCIDigestDecision(ctx, i, repo, "sha256:"+root.Digest, root.Path); !errors.Is(e, ErrDeleted) {
		t.Fatal(e)
	}
}

func TestLifecycleWeakSubjectAndRevokedGrantStayAuthoritative(t *testing.T) {
	db, ctx, i, repo, _, root := lifecycleFixture(t)
	attachment := Artifact{Path: "app/manifests/sha256:" + strings.Repeat("3", 64), Digest: strings.Repeat("3", 64), Size: 41, MediaType: integrationOCIIndex}
	m := OCIManifestMetadata{Validated: true, References: []string{}, Descriptors: map[string]OCIDescriptor{}, Subject: &OCIDescriptor{MediaType: root.MediaType, Digest: "sha256:" + root.Digest, Size: root.Size}}
	if e := publishOCIFixture(db, ctx, i, repo, attachment, m); e != nil {
		t.Fatal(e)
	}
	if _, e := db.DeleteOCI(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest, 10); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Artifact(ctx, i, repo, attachment.Path); !errors.Is(e, ErrDeleted) {
		t.Fatal("deleted subject became unobserved weak association", e)
	}
	writer := Identity{Tenant: i.Tenant, Actor: "restricted-writer", Role: "writer"}
	if e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET access='restricted' WHERE name=$1;`, repo)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,$2,$3,true,true)`, i.Tenant, repo, writer.Actor)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	input := lifecycleInput(attachment, "delete", 0)
	if _, e := db.ChangeArtifactState(ctx, writer, repo, "writer-lifecycle", "writer-fingerprint", input, 10, nil); e != nil {
		t.Fatal(e)
	}
	if e := db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.repository_grants SET can_read=false,can_write=false WHERE repository=$1 AND actor=$2`, repo, writer.Actor)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ChangeArtifactState(ctx, writer, repo, "writer-lifecycle", "writer-fingerprint", input, 10, nil); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked writer replayed lifecycle", e)
	}
	if _, _, e := db.ReplayArtifactLifecycle(ctx, writer, repo, "writer-lifecycle", "writer-fingerprint", input); !errors.Is(e, ErrDenied) {
		t.Fatal("pre-I/O replay bypassed current grant", e)
	}
}

func TestLifecycleRepositoryFencesPersistAfterResume(t *testing.T) {
	db, ctx, i, repo, _, _ := lifecycleFixture(t)
	proxy := Repository{Name: "lifecycle-proxy", Format: "oci", Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/v2/", Networks: []string{"127.0.0.1/32"}}}}
	if e := db.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, proxy) }); e != nil {
		t.Fatal(e)
	}
	lease, e := db.AcquireRetrieval(ctx, i, proxy.Name, "app/manifests/latest", "old-operation", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		return CreateUpload(ctx, tx, i, repo, "app", strings.Repeat("u", 43), 10, time.Hour)
	}); e != nil {
		t.Fatal(e)
	}
	u, e := db.ClaimUpload(ctx, i, repo, "app", strings.Repeat("u", 43), strings.Repeat("c", 43), 0, time.Minute, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{proxy.Name, repo} {
		input := RepositoryStateRequest{Action: "suspend", ExpectedRevision: 0, Reason: "maintenance", DryRun: true}
		if _, e = db.ChangeRepositoryState(ctx, i, name, "", "", input, 10); e != nil {
			t.Fatal(e)
		}
		state, e := db.RepositoryState(ctx, i, name)
		if e != nil || state.Revision != 0 {
			t.Fatal("preview changed state", state, e)
		}
		input.DryRun = false
		if _, e = db.ChangeRepositoryState(ctx, i, name, "", "", input, 10); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Repository(ctx, i, name); !errors.Is(e, ErrRepositorySuspended) {
			t.Fatal(e)
		}
		if _, e = db.ChangeRepositoryState(ctx, i, name, "", "", RepositoryStateRequest{Action: "resume", ExpectedRevision: 1}, 10); e != nil {
			t.Fatal(e)
		}
	}
	if e = db.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 404}); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("old retrieval revived", e)
	}
	if e = db.RenewUpload(ctx, i, u, time.Minute, time.Hour); !errors.Is(e, ErrUploadLeaseLost) {
		t.Fatal("old upload revived", e)
	}
	if _, e = db.ChangeRepositoryState(ctx, i, repo, "", "", RepositoryStateRequest{Action: "remove", ExpectedRevision: 2}, 10); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Repository(ctx, i, repo); !errors.Is(e, ErrRepositoryRemoved) {
		t.Fatal(e)
	}
	if _, e = db.ChangeRepositoryState(ctx, i, repo, "", "", RepositoryStateRequest{Action: "resume", ExpectedRevision: 3}, 10); !errors.Is(e, ErrConflict) {
		t.Fatal("resume bypassed restore", e)
	}
	if _, e = db.ChangeRepositoryState(ctx, i, repo, "", "", RepositoryStateRequest{Action: "restore", ExpectedRevision: 3}, 10); e != nil {
		t.Fatal(e)
	}
	if _, e = db.OCIManifest(ctx, i, repo, "app", "latest"); e != nil {
		t.Fatal("removal lost bytes", e)
	}
}

func TestLifecycleBudgetAndOutboxFailureRollBack(t *testing.T) {
	_, db, owner, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	proxy := Repository{Name: "lifecycle-bounded", Format: "generic", Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/", Networks: []string{"127.0.0.1/32"}}}}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, proxy) }); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"first", "second"} {
		if _, e = db.AcquireRetrieval(ctx, i, proxy.Name, path, path, true); e != nil {
			t.Fatal(e)
		}
	}
	input := RepositoryStateRequest{Action: "suspend", ExpectedRevision: 0, Reason: "bounded verification"}
	if _, e = db.ChangeRepositoryState(ctx, i, proxy.Name, "", "", input, 1); !errors.Is(e, ErrMetadataLimit) {
		t.Fatal("partial budget accepted", e)
	}
	state, e := db.RepositoryState(ctx, i, proxy.Name)
	if e != nil || state.Revision != 0 || state.State != "active" {
		t.Fatal(state, e)
	}
	before, e := db.Events(ctx, i, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(ctx, `CREATE FUNCTION cratectl_private.lifecycle_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned lifecycle outbox fault'; END $$; CREATE TRIGGER lifecycle_outbox_fault BEFORE INSERT ON cratectl.jobs FOR EACH ROW EXECUTE FUNCTION cratectl_private.lifecycle_outbox_fault()`); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ChangeRepositoryState(ctx, i, proxy.Name, "rollback-operation", "rollback-fingerprint", input, 10); e == nil {
		t.Fatal("fault accepted")
	}
	state, e = db.RepositoryState(ctx, i, proxy.Name)
	if e != nil || state.Revision != 0 || state.State != "active" {
		t.Fatal("state survived rollback", state, e)
	}
	after, e := db.Events(ctx, i, 0)
	if e != nil || len(after) != len(before) {
		t.Fatal("journal survived rollback", e)
	}
	for _, path := range []string{"first", "second"} {
		r, e := db.Retrieval(ctx, i, proxy.Name, path)
		if e != nil || r.State != "fetching" || r.Generation != 1 {
			t.Fatal("fence survived rollback", r, e)
		}
	}
	if _, found, e := db.ReplayMutation(ctx, i, "rollback-operation", "rollback-fingerprint"); e != nil || found {
		t.Fatal("receipt survived rollback", e)
	}
}
