// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func checksumFailureReport(t testing.TB, f checksumTimeline, snapshot crypt.GoSumDBSnapshot, pin []byte) GoChecksumFailureReport {
	t.Helper()
	r := GoChecksumFailureReport{Profile: GoChecksumFailureProfile, Module: f.Module, Version: "v1.0.0", ZIPHash: f.ZIPHashes["v1.0.0"], ModHash: f.ModHash, VerifierKey: f.Key, Checkpoint: bytes.Clone(pin)}
	paths := []string{}
	for path := range snapshot.Responses {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		r.Attempts = append(r.Attempts, GoChecksumFailureAttempt{Path: path, Status: 200, Code: "ok", Body: bytes.Clone(snapshot.Responses[path])})
	}
	return r
}

func checksumFailureRecord(t testing.TB) (checksumTimeline, GoChecksumFailureRecord) {
	t.Helper()
	f := checksumTimelineFixture(t)
	key, err := crypt.ParseGoSumDBCheckpoint(f.Key, f.One)
	if err != nil {
		t.Fatal(err)
	}
	r := GoChecksumFailureRecord{Profile: GoChecksumFailureEvidenceProfile, Tenant: "failure-team", Repository: "owned", RootPath: (gomodule.Coordinate{Module: f.Module, Version: "v1.0.0"}).Prefix() + ".zip", Generation: 2, KeyDigest: key.KeyDigest, ExpectedCheckpointRevision: 2, CurrentCheckpointRevision: 2, CurrentCheckpoint: bytes.Clone(f.One), Classification: "fork", Report: checksumFailureReport(t, f, f.Fork, f.One)}
	return f, r
}

func TestGoChecksumFailureClassificationRequiresIndependentTrustAndBoundedOriginalObservations(t *testing.T) {
	for _, scenario := range []string{"signed-fork", "valid-proof-is-not-approval", "missing-tiles", "corrupt-lookup", "corrupt-tile", "non200-fork-not-proof", "ambiguous-response", "wrong-key", "self-pin", "too-many", "large-body", "large-total", "unknown-code", "status", "control-path", "invalid-utf8", "no-store-omission", "bad-omission"} {
		t.Run(scenario, func(t *testing.T) {
			f := checksumTimelineFixture(t)
			r := checksumFailureReport(t, f, f.First, f.One)
			want := "unverified"
			wantErr := error(nil)
			switch scenario {
			case "signed-fork":
				r = checksumFailureReport(t, f, f.Fork, f.One)
				want = "fork"
			case "missing-tiles":
				r.Attempts = r.Attempts[:1]
			case "corrupt-lookup":
				r.Attempts[0].Body = []byte("untrusted malformed bytes")
			case "corrupt-tile":
				r.Attempts[len(r.Attempts)-1].Body[0] ^= 1
			case "non200-fork-not-proof":
				r = checksumFailureReport(t, f, f.Fork, f.One)
				for n := range r.Attempts {
					r.Attempts[n].Status, r.Attempts[n].Code = 503, "status"
				}
			case "ambiguous-response":
				conflict := r.Attempts[0]
				conflict.Body = []byte("ambiguous original response")
				r.Attempts = append(r.Attempts, conflict)
			case "wrong-key":
				r.VerifierKey += "x"
				wantErr = ErrGoModuleUnvalidated
			case "self-pin":
				r.Checkpoint = f.Initial
				wantErr = ErrGoModuleUnvalidated
			case "too-many":
				r.Attempts = make([]GoChecksumFailureAttempt, 129)
				wantErr = ErrGoModuleUnvalidated
			case "large-body":
				r.Attempts[0].Body = bytes.Repeat([]byte("x"), 64<<10+2)
				wantErr = ErrGoModuleUnvalidated
			case "large-total":
				r.Attempts = make([]GoChecksumFailureAttempt, 128)
				for n := range r.Attempts {
					r.Attempts[n] = GoChecksumFailureAttempt{Path: "/lookup/owned", Status: 503, Code: "status", Body: bytes.Repeat([]byte("x"), 8192)}
				}
				wantErr = ErrGoModuleUnvalidated
			case "unknown-code":
				r.Attempts[0].Code = "untrusted error text"
				wantErr = ErrGoModuleUnvalidated
			case "status":
				r.Attempts[0].Status = 503
				wantErr = ErrGoModuleUnvalidated
			case "control-path":
				r.Attempts[0].Path += "\n"
				wantErr = ErrGoModuleUnvalidated
			case "invalid-utf8":
				r.Attempts[0].Path = string([]byte{0xff})
				wantErr = ErrGoModuleUnvalidated
			case "no-store-omission", "bad-omission":
				r.Attempts = []GoChecksumFailureAttempt{{Path: r.Attempts[0].Path, Status: 200, Code: "cache_policy", Omitted: true, OmittedPrefixSHA256: crypt.Digest([]byte("owned omitted bytes")), OmittedPrefixBytes: len("owned omitted bytes")}}
				if scenario == "bad-omission" {
					r.Attempts[0].Body = []byte("policy-forbidden retention")
					wantErr = ErrGoModuleUnvalidated
				}
			}
			classification, err := classifyGoChecksumFailure(context.Background(), r, f.Key, f.One, f.One)
			if !errors.Is(err, wantErr) || err == nil && classification != want || err != nil && classification != "" {
				t.Fatal("failure observations conferred trust or incorrect fork classification", scenario, classification, err)
			}
		})
	}
}

func TestGoChecksumFailureEvidencePreservesCurrentWinnerAndRejectsAmbiguousExport(t *testing.T) {
	for _, scenario := range []string{"valid", "current-winner", "caller-classification", "wrong-key", "wrong-current-key", "noncanonical", "duplicate", "unknown", "trailing", "oversized", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f, record := checksumFailureRecord(t)
			ctx := context.Background()
			key := f.Key
			want := error(ErrGoModuleUnvalidated)
			switch scenario {
			case "valid":
				want = nil
			case "current-winner":
				record.ExpectedCheckpointRevision = 0
				record.Report.Checkpoint = f.Initial
				want = nil
			case "caller-classification":
				record.Classification = "unverified"
			case "wrong-key":
				key += "x"
				want = crypt.ErrGoChecksumAuthority
			case "wrong-current-key":
				record.CurrentCheckpoint = []byte("unsigned caller pin")
				want = crypt.ErrGoChecksumAuthority
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "noncanonical":
				raw = append([]byte(" "), raw...)
			case "duplicate":
				raw = append([]byte(`{"profile":"unknown",`), raw[1:]...)
			case "unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "oversized":
				raw = bytes.Repeat([]byte("x"), MaxGoChecksumFailureEvidence+1)
				want = ErrMetadataLimit
			}
			got, err := VerifyGoChecksumFailureEvidence(ctx, raw, key)
			if !errors.Is(err, want) || err == nil && !reflect.DeepEqual(got, record) || err != nil && !reflect.DeepEqual(got, GoChecksumFailureRecord{}) {
				t.Fatal("failure export gained approval or lost original proof/trust bindings", scenario, err)
			}
		})
	}
}

func FuzzGoChecksumFailureEvidence(f *testing.F) {
	fixture, record := checksumFailureRecord(f)
	seed, err := json.Marshal(record)
	if err != nil {
		f.Fatal(err)
	}
	if got, err := VerifyGoChecksumFailureEvidence(context.Background(), seed, fixture.Key); err != nil || got.Classification != "fork" {
		f.Fatal("stable public worker seed must independently prove a signed fork", err)
	}
	f.Add(seed)
	record.Classification = "unverified"
	record.Report.Attempts = []GoChecksumFailureAttempt{{Path: record.Report.Attempts[0].Path, Status: 200, Code: "cache_policy", Omitted: true, OmittedPrefixSHA256: crypt.Digest([]byte("owned omitted bytes")), OmittedPrefixBytes: len("owned omitted bytes")}}
	omitted, err := json.Marshal(record)
	if err != nil {
		f.Fatal(err)
	}
	if got, err := VerifyGoChecksumFailureEvidence(context.Background(), omitted, fixture.Key); err != nil || got.Classification != "unverified" {
		f.Fatal("omitted original bytes must stay unverified", err)
	}
	f.Add(omitted)
	f.Add([]byte(`{"profile":"unknown"}`))
	f.Add([]byte(strings.Repeat("x", 4097)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxGoChecksumFailureEvidence+1 {
			return
		}
		got, err := VerifyGoChecksumFailureEvidence(context.Background(), raw, fixture.Key)
		if err != nil && !reflect.DeepEqual(got, GoChecksumFailureRecord{}) {
			t.Fatal("invalid failure evidence exposed partial verified state")
		}
	})
}
