//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func TestGoModuleChecksumFailureInspectionPagesAndRetiredEvidence(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	for n := 0; n < 3; n++ {
		lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "inspection-history", true)
		if err != nil || !lease.Acquired {
			t.Fatal(err)
		}
		report := checksumFailureReport(t, log, log.First, log.One)
		if n == 2 {
			report = checksumFailureReport(t, log, log.Fork, log.One)
		}
		if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_unverified", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: report}}); err != nil {
			t.Fatal(err)
		}
	}
	first, more, err := f.s.GoChecksumFailurePage(ctx, f.i, "owned", 0, 2)
	if err != nil || len(first) != 2 || !more || first[0].Sequence >= first[1].Sequence || first[0].Classification != "unverified" {
		t.Fatal("bounded history lost ordering/lookahead", err, first, more)
	}
	last, more, err := f.s.GoChecksumFailurePage(ctx, f.i, "owned", first[1].Sequence, 2)
	if err != nil || len(last) != 1 || more || last[0].Classification != "fork" {
		t.Fatal("history cursor skipped or repeated an attempt", err, last, more)
	}
	if end, more, err := f.s.GoChecksumFailurePage(ctx, f.i, "owned", last[0].Sequence, 2); err != nil || len(end) != 0 || more {
		t.Fatal("terminal page", err)
	}
	summary, _ := json.Marshal(first)
	if bytes.Contains(summary, []byte("attempts")) || bytes.Contains(summary, []byte(log.Key)) || bytes.Contains(summary, []byte("checkpoint\":")) {
		t.Fatal("summary included raw observations or trust pins")
	}
	raw, digest, err := f.s.GoChecksumFailureEvidence(ctx, f.i, "owned", last[0].RootPath, last[0].SourceRevision, last[0].Generation)
	if err != nil || digest != last[0].EvidenceDigest || crypt.Digest(raw) != digest {
		t.Fatal("summary did not identify exact immutable evidence", err)
	}
	refs, jobs, ready := f.counts(t)
	for n, action := range []string{"suspend", "remove"} {
		if _, err := f.s.ChangeRepositoryState(ctx, f.i, "owned", "inspect-"+action, "inspect-"+action, RepositoryStateRequest{Action: action, ExpectedRevision: int64(n), Reason: "retain incident evidence during review"}, 100); err != nil {
			t.Fatal(err)
		}
		page, _, err := f.s.GoChecksumFailurePage(ctx, f.i, "owned", 0, 100)
		if err != nil || len(page) != 3 {
			t.Fatal("lifecycle hid original incident history", action, err)
		}
		retained, d, err := f.s.GoChecksumFailureEvidence(ctx, f.i, "owned", last[0].RootPath, 0, last[0].Generation)
		if err != nil || d != digest || !bytes.Equal(retained, raw) {
			t.Fatal("lifecycle altered or hid exact original bytes", action, err)
		}
		state, err := f.s.GoChecksumState(ctx, f.i, "owned", 0)
		if err != nil || !state.Blocked || state.Checkpoint.Revision != 2 {
			t.Fatal("inspection reset the key or lost retained trust", action, err)
		}
		if _, err = f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0); !errors.Is(err, ErrRepositorySuspended) && !errors.Is(err, ErrRepositoryRemoved) {
			t.Fatal("inspection permission admitted operational use", err)
		}
	}
	if a, b, c := f.counts(t); a != refs || b != jobs || c != ready {
		t.Fatal("inspection changed package references/integrity work/ready state", a, b, c)
	}
}

func TestGoModuleChecksumForkPrecedesFreshNegativeFallback(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	c, err := gomodule.Canonical(log.Module, "v1.9.9")
	if err != nil {
		t.Fatal("negative fallback control requires a canonical module/version", err)
	}
	negative, err := f.s.AcquireRetrieval(ctx, f.i, "owned", c.Prefix()+".zip", "negative-before-fork", false)
	if err != nil || !negative.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, negative, RetrievalResult{Status: 404, FreshSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	if absent, err := f.s.GoModuleProxyAbsent(ctx, f.i, "owned", c.Prefix()+".zip", 0); err != nil || !absent {
		t.Fatal("control must begin with a valid fresh negative fallback", err)
	}
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "observed-fork", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: checksumFailureReport(t, log, log.Fork, log.One)}}); err != nil {
		t.Fatal(err)
	}
	if absent, err := f.s.GoModuleProxyAbsent(ctx, f.i, "owned", c.Prefix()+".zip", 0); !errors.Is(err, ErrGoChecksumAuthorityBlocked) || absent {
		t.Fatal("a fresh negative bypassed a tenant/key block and admitted lower-source fallback", err)
	}
	state, err := f.s.Retrieval(ctx, f.i, "owned", lease.Path, 0)
	if err != nil || state.State != "failed" || state.LastError != "upstream_checksum_fork" || state.StalePermitted() {
		t.Fatal("operational key block hid the original failed state or admitted stale bytes", err)
	}
}
