//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func publishGoFailureFixture(t *testing.T) (goIntakeFixture, checksumTimeline) {
	t.Helper()
	f, log := newGoChecksumIntake(t)
	if err := f.s.CompleteRetrieval(context.Background(), f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	approveGoChecksumBundle(t, f)
	return f, log
}

func goFailureCounts(t *testing.T, f goIntakeFixture) (evidence, blocked int) {
	t.Helper()
	if err := f.s.Tx(context.Background(), f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM cratectl.go_checksum_failures),(SELECT count(*) FROM cratectl.go_checksum_forks)`).Scan(&evidence, &blocked)
	}); err != nil {
		t.Fatal(err)
	}
	return
}

func TestGoModuleChecksumFailureEvidenceAndKeyBlockAreAtomicWithoutOrdinaryQueueCapacity(t *testing.T) {
	for _, scenario := range []string{"fork", "unverified", "forged-fork-label", "integrity-full", "events-full"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := publishGoFailureFixture(t)
			ctx := context.Background()
			publishChecksumDiscoveryCatalog(t, f, log.Module, "v1.0.0\n")
			view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			oldAdmission := verifyStoredGoChecksum(t, f, view)
			lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "observed-failure", true)
			if err != nil || !lease.Acquired {
				t.Fatal(err)
			}
			if scenario == "integrity-full" || scenario == "events-full" {
				queue := strings.TrimSuffix(scenario, "-full")
				if _, err := f.s.SetQueuePolicy(ctx, f.i, "failure-capacity", "failure-capacity", QueuePolicy{Queue: queue, Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}); err != nil {
					t.Fatal(err)
				}
			}
			report := checksumFailureReport(t, log, log.Fork, log.One)
			want := "fork"
			if scenario == "unverified" || scenario == "forged-fork-label" {
				report = checksumFailureReport(t, log, log.First, log.One)
				want = "unverified"
				if scenario == "unverified" {
					report.Attempts = []GoChecksumFailureAttempt{{Path: report.Attempts[0].Path, Status: 503, Code: "status", Body: []byte("owned unverified original response")}}
				}
			}
			refs, jobs, ready := f.counts(t)
			var eventJobs int
			if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.jobs WHERE queue='events'`).Scan(&eventJobs)
			}); err != nil {
				t.Fatal(err)
			}
			if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: report}}); err != nil {
				t.Fatal("critical evidence/block depends on ordinary queue capacity", err)
			}
			raw, digest, err := f.s.GoChecksumFailureEvidence(ctx, f.i, "owned", lease.Path, 0, lease.Generation)
			if err != nil || crypt.Digest(raw) != digest {
				t.Fatal("original failure bytes lost", err)
			}
			record, err := VerifyGoChecksumFailureEvidence(ctx, raw, log.Key)
			if err != nil || record.Classification != want || !reflect.DeepEqual(record.Report, report) || record.Generation != lease.Generation || !bytes.Equal(record.CurrentCheckpoint, log.One) {
				t.Fatal("independent export lost original evidence or current trust", err)
			}
			state, err := f.s.GoChecksumState(ctx, f.i, "owned", 0)
			if err != nil || state.Blocked != (want == "fork") || state.Checkpoint.Revision != 2 || !bytes.Equal(state.Checkpoint.Checkpoint, log.One) {
				t.Fatal("failure reset trust or caller label established a key block", err)
			}
			if want == "fork" {
				if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
					t.Fatal("blocked key admitted a new collection", err)
				}
				if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", lease.Path, 0, oldAdmission.NativeAdmission()); !errors.Is(err, ErrGoChecksumAuthorityBlocked) && !errors.Is(err, ErrGoModuleUnvalidated) {
					t.Fatal("pre-fork proof admission served bytes", err)
				}
				if _, err = f.s.GoModuleView(ctx, f.i, "owned", log.Module, 100, 1<<20); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
					t.Fatal("blocked key remained discoverable", err)
				}
			}
			if a, b, c := f.counts(t); a != refs || b != jobs || c != ready {
				t.Fatal("control failure evidence created package references, integrity jobs or ready events", a, b, c)
			}
			if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
				var atomic bool
				err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.go_checksum_failures f JOIN cratectl.retrievals r ON (r.tenant,r.repository,r.path,r.source_revision,r.generation)=(f.tenant,f.repository,f.root_path,f.source_revision,f.generation) JOIN cratectl.events e ON e.tenant=f.tenant AND e.sequence=f.change_sequence WHERE f.repository='owned' AND f.evidence_digest=$1 AND r.state='failed' AND r.change_sequence=f.change_sequence AND e.payload::jsonb#>>'{data,go_checksum_failure_digest}'=$1) AND (SELECT count(*) FROM cratectl.jobs WHERE queue='events')=$2`, digest, eventJobs).Scan(&atomic)
				if err == nil && !atomic {
					t.Error("failure, journal, lease state and queue-independent effects were not atomic")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "replay", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: report}}); !errors.Is(err, ErrLeaseLost) {
				t.Fatal("same failed lease duplicated evidence", err)
			}
		})
	}
}

func TestGoModuleChecksumFailureRetainsSourceGrantLeaseAndEvidenceShapeFences(t *testing.T) {
	for _, scenario := range []string{"source", "expired", "token", "grant", "coordinate", "future-pin", "bad-observation"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := publishGoFailureFixture(t)
			ctx := context.Background()
			identity := f.i
			lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "fenced-failure", true)
			if err != nil || !lease.Acquired {
				t.Fatal(err)
			}
			failure := GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}
			want := error(ErrGoModuleUnvalidated)
			switch scenario {
			case "source":
				checksumDiscoveryFault(t, f, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`)
				want = ErrSourceChanged
			case "expired":
				checksumDiscoveryFault(t, f, `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE right(path,4)='.zip'`)
				want = ErrLeaseLost
			case "token":
				lease.Token += "wrong"
				want = ErrLeaseLost
			case "grant":
				token, err := crypt.Token()
				if err != nil {
					t.Fatal(err)
				}
				if err = Provision(ctx, f.d.OwnerDSN, f.i.Tenant, "failure-reader", "reader", token, time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				identity, err = f.s.Authenticate(ctx, token)
				if err != nil {
					t.Fatal(err)
				}
				want = ErrDenied
			case "coordinate":
				failure.Report.Version = "v1.1.0"
			case "future-pin":
				failure.ExpectedCheckpointRevision = 3
				want = ErrGoChecksumCheckpointChanged
			case "bad-observation":
				failure.Report.Attempts[0].Code = "caller verified"
			}
			if err = f.s.CompleteRetrieval(ctx, identity, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &failure}); !errors.Is(err, want) {
				t.Fatal("failure evidence bypassed current authority/lease/shape", scenario, err, want)
			}
			if a, b := goFailureCounts(t, f); a != 0 || b != 0 {
				t.Fatal("rejected observation left partial evidence or key block", a, b)
			}
		})
	}
}

func TestGoModuleChecksumForkBlocksTenantKeyAcrossRepositoriesPublicationAndSourceChanges(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	repository, err := f.s.Repository(ctx, f.i, "owned")
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := json.Marshal(repository.Settings)
	if err = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings) VALUES($1,'sibling','go','proxy',true,'restricted',$2)`, f.i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	alias, err := f.s.AcquireRetrieval(ctx, f.i, "sibling", f.lease.Path, "sibling-verified", false)
	if err != nil || !alias.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, alias, f.result); err != nil {
		t.Fatal(err)
	}
	checksumDiscoveryFault(t, f, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='sibling' AND NOT starts_with(path,'go-checksum/')`)
	view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "sibling", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldAdmission := verifyStoredGoChecksum(t, f, view)
	next := f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, "assets/inert.txt", log.Payload)
	attachGoChecksum(t, f, &next, log.publication(t, "v1.1.0", log.Second, 2))
	inflight, err := f.s.AcquireRetrieval(ctx, f.i, "sibling", next.GoModule.Objects[0].Path, "inflight-before-fork", false)
	if err != nil || !inflight.Acquired {
		t.Fatal(err)
	}
	failed, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "tenant-key-fork", true)
	if err != nil || !failed.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, failed, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "sibling", alias.Path, 0, oldAdmission.NativeAdmission()); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("same-key sibling used a pre-fork physical proof admission", err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, inflight, next); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("in-flight sibling published after another repository's fork", err)
	}
	if err = f.s.RenewRetrieval(ctx, f.i, inflight, time.Minute); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("blocked key renewed in-flight upstream work", err)
	}
	if _, err = f.s.AcquireRetrieval(ctx, f.i, "sibling", alias.Path, "blocked-new-fill", true); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("blocked key acquired new upstream work", err)
	}
	if err = f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var refs int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.artifacts WHERE repository='sibling' AND path=$1`, inflight.Path).Scan(&refs)
		if err == nil && refs != 0 {
			t.Error("blocked publication left partial bundle references")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		if err := CreateRepository(ctx, tx, f.i, Repository{Name: "lower", Format: "go", Access: "restricted"}); err != nil {
			return err
		}
		for _, group := range []Repository{{Name: "combined", Format: "go", Mode: "group", Access: "restricted", Settings: RepositorySettings{Members: []string{"sibling", "lower"}}}, {Name: "pinned", Format: "go", Mode: "group", Access: "restricted", Settings: RepositorySettings{Members: []string{"sibling", "lower"}, NamespaceOwners: map[string]string{"go.cratectl.invalid/!owned/": "lower"}}}} {
			if err := CreateRepository(ctx, tx, f.i, group); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.PublishGoModule(ctx, f.i, "lower", f.result.GoModule.Objects, "lower-fork-shadow"); err != nil {
		t.Fatal(err)
	}
	checksumDiscoveryFault(t, f, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='lower'`)
	if _, err = f.s.GoModuleView(ctx, f.i, "combined", log.Module, 100, 1<<20); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("group fell through a blocked checksum authority", err)
	}
	if versions, err := f.s.GoModuleVersions(ctx, f.i, "pinned", log.Module, 100, 1<<20); err != nil || !reflect.DeepEqual(versions, []string{"v1.0.0"}) {
		t.Fatal("explicit namespace owner could not select a separately governed source", err, versions)
	}
	a := log.authority()
	setGoChecksumAuthority(t, f, &a, true)
	if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 1); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("same-key source epoch reset a fork block", err)
	}
	other, _, _ := checksumPublicFixture(t)
	setGoChecksumAuthority(t, f, &other, true)
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 2)
	if err != nil || state.Blocked || state.Checkpoint.Revision != 0 {
		t.Fatal("separately trusted different key inherited old-key state", err)
	}
	setGoChecksumAuthority(t, f, &a, true)
	if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 3); !errors.Is(err, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("switching keys away and back rehabilitated a signed fork", err)
	}
	token, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = Provision(ctx, f.d.OwnerDSN, "failure-isolated", "operator", "admin", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	isolated, err := f.s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Tx(ctx, isolated, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) VALUES($1,'owned','go','proxy','restricted',$2)`, isolated.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if state, err := f.s.GoChecksumState(ctx, isolated, "owned", 0); err != nil || state.Blocked || state.Checkpoint.Revision != 0 {
		t.Fatal("tenant borrowed another tenant's fork/head", err)
	}
	if raw, digest, err := f.s.GoChecksumFailureEvidence(ctx, isolated, "owned", failed.Path, 0, failed.Generation); !errors.Is(err, ErrNotFound) || raw != nil || digest != "" {
		t.Fatal("tenant leaked another tenant's original failure bytes", err)
	}
}

func TestGoModuleChecksumFailureUpgradeAndRuntimeImmutability(t *testing.T) {
	testHoldUpgradePreservesReceiptsAndJournal(t, 12)
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "immutable-failure", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}}); err != nil {
		t.Fatal(err)
	}
	conn, err := f.s.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, table := range []string{"go_checksum_failures", "go_checksum_forks"} {
		var visible int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{"cratectl", table}.Sanitize()).Scan(&visible); err != nil || visible != 0 {
			t.Fatal("unscoped runtime leaked checksum failure evidence", table, visible, err)
		}
		for _, sql := range []string{`DELETE FROM ` + pgx.Identifier{"cratectl", table}.Sanitize() + ` WHERE false`, `UPDATE ` + pgx.Identifier{"cratectl", table}.Sanitize() + ` SET change_sequence=change_sequence WHERE false`} {
			err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql); return err })
			var postgres *pgconn.PgError
			if !errors.As(err, &postgres) || postgres.Code != "42501" {
				t.Fatal("runtime can rewrite/delete immutable failure evidence or rehabilitate a key", table, err)
			}
		}
	}
}

func TestGoModuleChecksumForkAndPublicationRacePreservesOneTimelineAndDeniesFinalReads(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	configured, err := f.s.Repository(ctx, f.i, "owned")
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := json.Marshal(configured.Settings)
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) VALUES($1,'racing','go','proxy','restricted',$2)`, f.i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	next := f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, "assets/inert.txt", log.Payload)
	attachGoChecksum(t, f, &next, log.publication(t, "v1.1.0", log.Second, 2))
	publication, err := f.s.AcquireRetrieval(ctx, f.i, "racing", next.GoModule.Objects[0].Path, "racing-publication", false)
	if err != nil || !publication.Acquired {
		t.Fatal(err)
	}
	failure, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "racing-fork", true)
	if err != nil || !failure.Acquired {
		t.Fatal(err)
	}
	report := checksumFailureReport(t, log, log.Fork, log.One)
	start := make(chan struct{})
	published, failed := make(chan error, 1), make(chan error, 1)
	go func() { <-start; published <- f.s.CompleteRetrieval(ctx, f.i, publication, next) }()
	go func() {
		<-start
		failed <- f.s.CompleteRetrieval(ctx, f.i, failure, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: report}})
	}()
	close(start)
	publicationErr, failureErr := <-published, <-failed
	if failureErr != nil || publicationErr != nil && !errors.Is(publicationErr, ErrGoChecksumAuthorityBlocked) {
		t.Fatal("concurrent fork/publication escaped the common tenant transaction", publicationErr, failureErr)
	}
	state, err := f.s.GoChecksumState(ctx, f.i, "racing", 0)
	if err != nil || !state.Blocked {
		t.Fatal("racing publication erased key governance", err)
	}
	wantRevision, wantHead, wantRefs := int64(2), log.One, 0
	if publicationErr == nil {
		wantRevision, wantHead, wantRefs = 3, log.Two, 3
	}
	if state.Checkpoint.Revision != wantRevision || !bytes.Equal(state.Checkpoint.Checkpoint, wantHead) {
		t.Fatal("race replaced or reset the signed timeline", state.Checkpoint.Revision, wantRevision)
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var refs int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.artifacts WHERE repository='racing' AND path=ANY($1::text[])`, []string{publication.Path, strings.TrimSuffix(publication.Path, ".zip") + ".mod", strings.TrimSuffix(publication.Path, ".zip") + ".info"}).Scan(&refs)
		if err == nil && refs != wantRefs {
			t.Error("race left a partial bundle", refs, wantRefs)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GoModuleChecksumReadback(ctx, f.i, "racing", gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, 0); !errors.Is(err, ErrGoChecksumAuthorityBlocked) && !errors.Is(err, ErrGoModuleCacheExpired) {
		t.Fatal("post-race read admitted blocked-key package bytes", err)
	}
	raw, _, err := f.s.GoChecksumFailureEvidence(ctx, f.i, "owned", failure.Path, 0, failure.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := VerifyGoChecksumFailureEvidence(ctx, raw, log.Key); err != nil || record.Classification != "fork" || record.CurrentCheckpointRevision != wantRevision {
		t.Fatal("racing evidence lost the independently retained winning pin", err)
	}
}

func TestGoModuleChecksumFailureSchemaSafetyRequiresBothForcedTenantTables(t *testing.T) {
	for _, table := range []string{"go_checksum_failures", "go_checksum_forks"} {
		t.Run(table, func(t *testing.T) {
			d, _, owner, _, _ := schemaFixture(t)
			ctx := context.Background()
			if _, err := owner.Exec(ctx, `ALTER TABLE `+pgx.Identifier{"cratectl", table}.Sanitize()+` NO FORCE ROW LEVEL SECURITY`); err != nil {
				t.Fatal(err)
			}
			opened, err := Open(ctx, d.RuntimeDSN)
			if opened != nil {
				opened.Pool.Close()
			}
			if !errors.Is(err, ErrSchemaIncompatible) {
				t.Fatal("runtime admitted an unforced failure/fork tenant table", err)
			}
		})
	}
}

func TestGoModuleChecksumForkEvidenceDoesNotExposeAnUnrelatedRepository(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "private-failure", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}}); err != nil {
		t.Fatal(err)
	}
	token, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = Provision(ctx, f.d.OwnerDSN, f.i.Tenant, "private-failure-reader", "reader", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	reader, err := f.s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'owned','private-failure-reader',true,false)`, f.i.Tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if raw, digest, err := f.s.GoChecksumFailureEvidence(ctx, reader, "owned", lease.Path, 0, lease.Generation); !errors.Is(err, ErrDenied) || len(raw) != 0 || digest != "" {
		t.Fatal("raw upstream failure bodies leaked through an ordinary repository-read grant", err)
	}
	state, err := f.s.GoChecksumState(ctx, f.i, "owned", 0)
	encoded, _ := json.Marshal(state)
	if err != nil || !state.Blocked || bytes.Contains(encoded, []byte(log.Module)) || bytes.Contains(encoded, []byte("owned")) {
		t.Fatal("key status leaked observing repository/module coordinates", err)
	}
}
