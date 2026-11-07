//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func newGoChecksumIntake(t *testing.T) (goIntakeFixture, checksumTimeline) {
	t.Helper()
	log := checksumTimelineFixture(t)
	f := newGoIntakeFixtureAt(t, gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, "assets/inert.txt", log.Payload)
	a := log.authority()
	setGoChecksumAuthority(t, f, &a, false)
	attachGoChecksum(t, f, &f.result, log.publication(t, "v1.0.0", log.First, 0))
	return f, log
}

func setGoChecksumAuthority(t *testing.T, f goIntakeFixture, a *GoChecksumAuthority, advanceSource bool) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"go_checksum_authority": a})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Tx(context.Background(), f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE cratectl.repositories SET settings=settings||$1::jsonb,source_revision=source_revision+$2 WHERE name='owned'`, raw, map[bool]int{true: 1, false: 0}[advanceSource])
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func attachGoChecksum(t *testing.T, f goIntakeFixture, result *RetrievalResult, p GoModuleChecksumPublication) {
	t.Helper()
	ctx := context.Background()
	c := gomodule.Coordinate{Module: p.Proof.Module, Version: p.Proof.Version}
	files := map[string][]byte{}
	var zipObject Artifact
	for _, a := range result.GoModule.Objects {
		file, err := f.objects.OpenVerified(ctx, f.i.Tenant, a.Digest, a.Size)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(a.Path, ".zip") {
			zipObject = a
			file.Close()
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(file, 64<<10))
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[a.Path] = raw
	}
	zipFile, err := f.objects.OpenVerified(ctx, f.i.Tenant, zipObject.Digest, zipObject.Size)
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := gomodule.InspectRepresentations(ctx, zipFile, zipObject.Size, c, files[c.Prefix()+".mod"], files[c.Prefix()+".info"], ziparchive.Limits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64})
	zipFile.Close()
	if err != nil || inspected.ZIPHash != p.ZIPHash || inspected.GoModHash != p.ModHash {
		t.Fatal("signed h1 must bind independently inspected staged bytes", err)
	}
	raw, err := json.Marshal(p.Proof)
	if err != nil {
		t.Fatal(err)
	}
	object, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(raw), p.Object.Digest, p.Object.Size)
	if err != nil {
		t.Fatal(err)
	}
	p.Object = object
	result.GoModule.Checksum = &p
}

func checksumRowCounts(t *testing.T, f goIntakeFixture) (heads, history, receipts int) {
	t.Helper()
	ctx := context.Background()
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		for _, q := range []struct {
			table string
			n     *int
		}{{"go_checksum_checkpoints", &heads}, {"go_checksum_checkpoint_revisions", &history}, {"go_module_checksum_receipts", &receipts}} {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{"cratectl", q.table}.Sanitize()).Scan(q.n); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

func TestGoModuleChecksumPublishesProofHistoryAndBundleAtomically(t *testing.T) {
	f, log := newGoChecksumIntake(t)
	ctx := context.Background()
	initial, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", f.lease.SourceRevision)
	if err != nil || initial.Revision != 0 || !bytes.Equal(initial.Checkpoint, log.Initial) {
		t.Fatal("explicit bootstrap view", err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	if a, b, c := f.counts(t); a != 4 || b != 4 || c != 1 {
		t.Fatal("proof, bundle, all integrity work and ready event must commit together", a, b, c)
	}
	if h, r, p := checksumRowCounts(t, f); h != 1 || r != 2 || p != 1 {
		t.Fatal("initial and advanced trust must be immutable and receipt bound", h, r, p)
	}
	current, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", f.lease.SourceRevision)
	if err != nil || current.Revision != 2 || !bytes.Equal(current.Checkpoint, log.One) {
		t.Fatal("current retained head", err)
	}
	p := f.result.GoModule.Checksum
	if err = f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var bound bool
		err := tx.QueryRow(ctx, `SELECT c.key_digest=$1 AND c.checkpoint_revision=2 AND c.proof_digest=$2 AND c.proof_size=$3 AND c.zip_digest=$4 AND c.mod_digest=$5 AND c.info_digest=$6 AND c.validation_generation=$7 AND c.source_revision=$8 AND c.change_sequence=r.change_sequence AND c.change_sequence=a.change_sequence AND proof.decision='unassessed' FROM cratectl.go_module_checksum_receipts c JOIN cratectl.retrievals r ON r.tenant=c.tenant AND r.repository=c.repository AND r.path=c.root_path JOIN cratectl.go_checksum_checkpoint_revisions a ON a.tenant=c.tenant AND a.key_digest=c.key_digest AND a.revision=c.checkpoint_revision JOIN cratectl.artifacts proof ON proof.tenant=c.tenant AND proof.repository=c.repository AND proof.path=c.proof_path WHERE c.repository='owned'`, current.KeyDigest, p.Object.Digest, p.Object.Size, f.result.GoModule.Objects[0].Digest, f.result.GoModule.Objects[1].Digest, f.result.GoModule.Objects[2].Digest, f.lease.Generation, f.lease.SourceRevision).Scan(&bound)
		if err == nil && !bound {
			t.Error("receipt lost exact raw objects, lease, sequence or unassessed policy")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("same lease republished", err)
	}
	// Serving remains closed until actual proof readback/current-policy admission.
	if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, f.lease.SourceRevision); !errors.Is(err, ErrGoModuleUnvalidated) {
		t.Fatal("publication enabled unfinished cached serving", err)
	}
}

func TestGoModuleChecksumConcurrentCollectorsCoalesceAndAdvanceWithoutReset(t *testing.T) {
	for _, scenario := range []string{"identical", "advance", "older-lookup"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			result := f.result
			root := f.lease.Path
			wantRevision, wantHistory := int64(2), 2
			if scenario != "identical" {
				result = f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, "assets/inert.txt", log.Payload)
				root = result.GoModule.Objects[0].Path
				attachGoChecksum(t, f, &result, log.publication(t, "v1.1.0", log.Second, 2))
				wantRevision = 3
				wantHistory = 3
			}
			lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", root, "parallel-collected-head", true)
			if err != nil || !lease.Acquired {
				t.Fatal(err)
			}
			if err = f.s.CompleteRetrieval(ctx, f.i, lease, result); err != nil {
				t.Fatal("consistent offline concurrent publication", err)
			}
			if scenario == "older-lookup" {
				old := f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, "assets/inert.txt", log.Payload)
				attachGoChecksum(t, f, &old, log.publication(t, "v1.0.0", log.OldAtSecond, 2))
				lease, err = f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "older-proof-newer-head", true)
				if err != nil || !lease.Acquired {
					t.Fatal(err)
				}
				if err = f.s.CompleteRetrieval(ctx, f.i, lease, old); err != nil {
					t.Fatal("older lookup must retain consistent newer head", err)
				}
			}
			current, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0)
			if err != nil || current.Revision != wantRevision {
				t.Fatal("head reset or duplicated", current.Revision, err)
			}
			if h, r, _ := checksumRowCounts(t, f); h != 1 || r != wantHistory {
				t.Fatal("identical winner must coalesce, extension append exactly once", h, r)
			}
			// A source epoch change and an older configured bootstrap cannot reset
			// the same key's timeline, even while all package cache epochs expire.
			a := log.authority()
			setGoChecksumAuthority(t, f, &a, true)
			after, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 1)
			if err != nil || !bytes.Equal(after.Checkpoint, current.Checkpoint) || after.Revision != current.Revision {
				t.Fatal("source configuration reset retained trust", err)
			}
		})
	}
}

func TestGoModuleChecksumRejectedPublicationRollsBackTrustAndReferences(t *testing.T) {
	for _, scenario := range []string{"integrity-capacity", "event-capacity", "expired-lease", "source-change", "wrong-proof-object", "untrusted-pin", "future-checkpoint-revision", "checksum-substitution", "immutable-bundle-conflict", "denied-grant", "wrong-tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			identity := f.i
			want := ErrGoModuleUnvalidated
			switch scenario {
			case "integrity-capacity", "event-capacity":
				queue := "integrity"
				capacity := 1
				if scenario == "event-capacity" {
					queue = "events"
					capacity = 1
				}
				_, err := f.s.SetQueuePolicy(ctx, f.i, "bounded-checksum-"+queue, "bounded-checksum-"+queue, QueuePolicy{Queue: queue, Capacity: capacity, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2})
				if err != nil {
					t.Fatal(err)
				}
				want = ErrQueueFull
			case "expired-lease", "source-change":
				if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					sql := `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='owned'`
					if scenario == "source-change" {
						sql = `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`
					}
					_, err := tx.Exec(ctx, sql)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				want = ErrLeaseLost
				if scenario == "source-change" {
					want = ErrSourceChanged
				}
			case "wrong-proof-object":
				f.result.GoModule.Checksum.Object.Digest = strings.Repeat("0", 64)
			case "untrusted-pin":
				p := log.publication(t, "v1.0.0", log.First, 0)
				p.Proof.Snapshot.Checkpoint = log.One
				raw, _ := json.Marshal(p.Proof)
				p.Object.Digest = crypt.Digest(raw)
				p.Object.Size = int64(len(raw))
				f.result.GoModule.Checksum = &p
				want = crypt.ErrGoChecksumAuthority
			case "future-checkpoint-revision":
				f.result.GoModule.Checksum.ExpectedCheckpointRevision = 1
				want = ErrGoChecksumCheckpointChanged
			case "checksum-substitution":
				f.result.GoModule.Checksum.ZIPHash = log.ModHash
			case "immutable-bundle-conflict":
				if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					a := f.result.GoModule.Objects[1]
					_, err := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata) VALUES($1,'owned',$2,$3,$4,$5,$6)`, f.i.Tenant, a.Path, strings.Repeat("a", 64), a.Size, a.MediaType, a.Metadata)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				want = ErrConflict
			case "denied-grant", "wrong-tenant":
				token, err := crypt.Token()
				if err != nil {
					t.Fatal(err)
				}
				tenant := f.i.Tenant
				if scenario == "wrong-tenant" {
					tenant = "checksum-other-team"
				}
				if err = Provision(ctx, f.d.OwnerDSN, tenant, "checksum-reader", "reader", token, time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				identity, err = f.s.Authenticate(ctx, token)
				if err != nil {
					t.Fatal(err)
				}
				want = ErrDenied
				if scenario == "wrong-tenant" {
					want = ErrNotFound
				}
			}
			if err := f.s.CompleteRetrieval(ctx, identity, f.lease, f.result); !errors.Is(err, want) {
				t.Fatal("rejected admission lost its fence", scenario, err)
			}
			wantRefs := 0
			if scenario == "immutable-bundle-conflict" {
				wantRefs = 1
			}
			if a, b, c := f.counts(t); a != wantRefs || b != 0 || c != 0 {
				t.Fatal("rejected publication left references, work or ready event", a, b, c)
			}
			if a, b, c := checksumRowCounts(t, f); a != 0 || b != 0 || c != 0 {
				t.Fatal("failed publication advanced trust or retained receipt", a, b, c)
			}
		})
	}
}

func TestGoModuleChecksumUpgradeRetainsElevenReceiptsAndEnforcesRLS(t *testing.T) {
	testHoldUpgradePreservesReceiptsAndJournal(t, 11)
	f, _ := newGoChecksumIntake(t)
	ctx := context.Background()
	if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	conn, err := f.s.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, table := range []string{"go_checksum_checkpoints", "go_checksum_checkpoint_revisions", "go_module_checksum_receipts"} {
		var visible int
		if err = conn.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{"cratectl", table}.Sanitize()).Scan(&visible); err != nil || visible != 0 {
			t.Fatal("unscoped runtime bypassed forced RLS", table, visible, err)
		}
		var update, del bool
		if err = conn.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,'UPDATE'),has_table_privilege(current_user,$1,'DELETE')`, "cratectl."+table).Scan(&update, &del); err != nil || update || del {
			t.Fatal("runtime can rewrite/delete immutable trust history or receipt", table, err)
		}
	}
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var restricted bool
		err := tx.QueryRow(ctx, `SELECT NOT r.rolsuper AND NOT r.rolbypassrls AND r.oid<>c.relowner AND c.relrowsecurity AND c.relforcerowsecurity FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE r.rolname=current_user AND n.nspname='cratectl' AND c.relname='go_checksum_checkpoint_revisions'`).Scan(&restricted)
		if err == nil && !restricted {
			t.Error("checksum runtime is owner/superuser/BYPASSRLS or missing forced RLS")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumTimelineSurvivesRepositoryChangesAndSeparatesTenantsAndKeys(t *testing.T) {
	f, log := newGoChecksumIntake(t)
	ctx := context.Background()
	if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	a := log.authority()
	settings, _ := json.Marshal(RepositorySettings{Upstream: &a.Endpoint, GoChecksumAuthority: &a})
	insert := func(identity Identity, name string) {
		t.Helper()
		if err := f.s.Tx(ctx, identity, true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) VALUES($1,$2,'go','proxy','restricted',$3)`, identity.Tenant, name, settings)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert(f.i, "sibling")
	shared, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "sibling", 0)
	if err != nil || shared.Revision != 2 || !bytes.Equal(shared.Checkpoint, log.One) {
		t.Fatal("same tenant/key got a fresh timeline in another repository", err)
	}
	other, _, _ := checksumPublicFixture(t)
	setGoChecksumAuthority(t, f, &other, true)
	separate, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 1)
	if err != nil || separate.Revision != 0 || separate.KeyDigest == shared.KeyDigest {
		t.Fatal("different verifier key inherited another key's history", err)
	}
	setGoChecksumAuthority(t, f, &a, true)
	returned, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 2)
	if err != nil || returned.Revision != 2 || !bytes.Equal(returned.Checkpoint, log.One) {
		t.Fatal("switching away and back reset trust", err)
	}
	token, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = Provision(ctx, f.d.OwnerDSN, "checksum-isolated-team", "operator", "admin", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	isolated, err := f.s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	insert(isolated, "owned")
	isolatedHead, err := f.s.GoModuleChecksumCheckpoint(ctx, isolated, "owned", 0)
	if err != nil || isolatedHead.Revision != 0 || !bytes.Equal(isolatedHead.Checkpoint, log.Initial) {
		t.Fatal("tenant inherited another tenant's retained trust", err)
	}
	if err = f.s.Tx(ctx, isolated, false, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.go_module_checksum_receipts`).Scan(&n)
		if err == nil && n != 0 {
			t.Error("another tenant's package receipt visible")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumForkAndMissingTilesPreserveCurrentTrust(t *testing.T) {
	for _, scenario := range []string{"signed-fork", "missing-consistency-tiles"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			want := crypt.ErrGoChecksumFork
			if scenario == "missing-consistency-tiles" {
				next := f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, "assets/inert.txt", log.Payload)
				attachGoChecksum(t, f, &next, log.publication(t, "v1.1.0", log.Second, 2))
				lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", next.GoModule.Objects[0].Path, "advance-before-stale-collector", false)
				if err != nil || !lease.Acquired {
					t.Fatal(err)
				}
				if err = f.s.CompleteRetrieval(ctx, f.i, lease, next); err != nil {
					t.Fatal(err)
				}
				want = ErrGoChecksumCheckpointChanged
			} else {
				// Deliberately adversarial internal publication: a valid same-key
				// fork proposes conflicting h1 values. It cannot replace trust or
				// gain references, regardless of its staged JSON's valid digest.
				p := log.publication(t, "v1.0.0", log.Fork, 0)
				p.ZIPHash = log.ModHash
				p.Proof.ZIPHash = log.ModHash
				raw, _ := json.Marshal(p.Proof)
				object, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(raw), crypt.Digest(raw), int64(len(raw)))
				if err != nil {
					t.Fatal(err)
				}
				p.Object = object
				f.result.GoModule.Checksum = &p
			}
			before, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0)
			if err != nil {
				t.Fatal(err)
			}
			refs, jobs, ready := f.counts(t)
			h, r, p := checksumRowCounts(t, f)
			lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "rejected-checksum-collector", true)
			if err != nil || !lease.Acquired {
				t.Fatal(err)
			}
			if err = f.s.CompleteRetrieval(ctx, f.i, lease, f.result); !errors.Is(err, want) {
				t.Fatal("fork/unavailable evidence classification lost", err)
			}
			after, err := f.s.GoChecksumState(ctx, f.i, "owned", 0)
			if err != nil || before.Revision != after.Checkpoint.Revision || !bytes.Equal(before.Checkpoint, after.Checkpoint.Checkpoint) || after.Blocked != (scenario == "signed-fork") {
				t.Fatal("rejected proof changed retained trust", err)
			}
			if a, b, c := f.counts(t); a != refs || b != jobs || c != ready {
				t.Fatal("rejected proof changed reference/work/publication counts", a, b, c)
			}
			if a, b, c := checksumRowCounts(t, f); a != h || b != r || c != p {
				t.Fatal("rejected proof appended trust or receipt", a, b, c)
			}
		})
	}
}

func TestGoModuleChecksumConcurrentRepositoriesShareOneWinningTimeline(t *testing.T) {
	f, log := newGoChecksumIntake(t)
	ctx := context.Background()
	a := log.authority()
	settings, _ := json.Marshal(RepositorySettings{Upstream: &a.Endpoint, GoChecksumAuthority: &a})
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) VALUES($1,'sibling','go','proxy','restricted',$2)`, f.i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sibling, err := f.s.AcquireRetrieval(ctx, f.i, "sibling", f.lease.Path, "concurrent-repository-lease", false)
	if err != nil || !sibling.Acquired {
		t.Fatal(err)
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	for _, lease := range []Retrieval{f.lease, sibling} {
		go func() { <-start; done <- f.s.CompleteRetrieval(ctx, f.i, lease, f.result) }()
	}
	close(start)
	for n := 0; n < 2; n++ {
		if err = <-done; err != nil {
			t.Fatal("concurrent same-key publication failed", err)
		}
	}
	if h, r, p := checksumRowCounts(t, f); h != 1 || r != 2 || p != 2 {
		t.Fatal("same-key concurrent winner duplicated/reset history or lost scoped receipt", h, r, p)
	}
	if err = f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var references, integrity, ready int
		err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.artifacts),(SELECT count(*) FROM cratectl.jobs WHERE queue='integrity'),(SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='proxy.retrieval.ready')`).Scan(&references, &integrity, &ready)
		if err == nil && (references != 8 || integrity != 8 || ready != 2) {
			t.Error("concurrent publications lost independent repository intents", references, integrity, ready)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumRuntimeCannotRollBackHeadOrRewriteHistory(t *testing.T) {
	f, _ := newGoChecksumIntake(t)
	ctx := context.Background()
	if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ sql, code string }{{`UPDATE cratectl.go_checksum_checkpoints SET revision=1`, "P0001"}, {`UPDATE cratectl.go_checksum_checkpoint_revisions SET root_hash=root_hash`, "42501"}, {`DELETE FROM cratectl.go_module_checksum_receipts WHERE false`, "42501"}} {
		err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, attempt.sql); return err })
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != attempt.code {
			t.Fatal("runtime did not enforce the specific monotonic-head or immutable-history restriction", err)
		}
	}
	head, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0)
	if err != nil || head.Revision != 2 {
		t.Fatal("failed runtime mutations changed head", err)
	}
}

func TestGoModuleChecksumSchemaSafetyFailsClosedForEveryNewTable(t *testing.T) {
	for _, table := range []string{"go_checksum_checkpoints", "go_checksum_checkpoint_revisions", "go_module_checksum_receipts"} {
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
				t.Fatal("runtime admitted an unforced checksum tenant table", err)
			}
		})
	}
}
