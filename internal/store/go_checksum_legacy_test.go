// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
)

func legacyEvidenceFixture(t testing.TB) GoChecksumLegacyEvidence {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"tenant": "legacy-team", "sequence": 7, "actor": "operator", "kind": "proxy.retrieval.failed", "data": map[string]any{"repository": "old-source", "path": "example.org/owned/@v/v1.0.0.zip", "failure": "upstream_checksum_fork", "source_revision": 0, "generation": 2}})
	if err != nil {
		t.Fatal(err)
	}
	previous := strings.Repeat("a", 64)
	hash := crypt.Digest(append([]byte(previous+"\n"), payload...))
	return GoChecksumLegacyEvidence{Incident: GoChecksumLegacyIncident{Sequence: 7, EventHash: hash}, OriginalEvent: Event{Sequence: 7, Payload: string(payload), PreviousHash: previous, Hash: hash}}
}

func TestGoChecksumLegacyEvidenceRetainsUnknownProofAndExactJournalBindings(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-tenant", "payload-tenant", "row-sequence", "payload-sequence", "corrupt-body", "row-hash", "previous", "bad-previous", "zero-sequence", "malformed", "kind", "failure", "overflow", "claimed-fork", "tenant-case-alias", "failure-case-alias"} {
		t.Run(scenario, func(t *testing.T) {
			out := legacyEvidenceFixture(t)
			tenant := "legacy-team"
			rehash := false
			switch scenario {
			case "wrong-tenant":
				tenant = "another-team"
			case "payload-tenant":
				out.OriginalEvent.Payload = strings.Replace(out.OriginalEvent.Payload, "legacy-team", "another-team", 1)
				rehash = true
			case "row-sequence":
				out.Incident.Sequence++
			case "payload-sequence":
				out.OriginalEvent.Payload = strings.Replace(out.OriginalEvent.Payload, `"sequence":7`, `"sequence":8`, 1)
				rehash = true
			case "corrupt-body":
				out.OriginalEvent.Payload += " "
			case "row-hash":
				out.Incident.EventHash = strings.Repeat("0", 64)
			case "previous":
				out.OriginalEvent.PreviousHash = strings.Repeat("b", 64)
			case "bad-previous":
				out.OriginalEvent.PreviousHash = "not a chain hash"
				rehash = true
			case "zero-sequence":
				out.Incident.Sequence = 0
				out.OriginalEvent.Sequence = 0
			case "malformed":
				out.OriginalEvent.Payload = "{"
				rehash = true
			case "kind":
				out.OriginalEvent.Payload = strings.Replace(out.OriginalEvent.Payload, "proxy.retrieval.failed", "proxy.retrieval.ready", 1)
				rehash = true
			case "failure":
				out.OriginalEvent.Payload = strings.Replace(out.OriginalEvent.Payload, "upstream_checksum_fork", "transient_upstream_failure", 1)
				rehash = true
			case "overflow":
				out.OriginalEvent.Payload = strings.Repeat("x", MaxGoChecksumLegacyEvent+1)
			case "claimed-fork":
				out.Classification = "fork"
			case "tenant-case-alias":
				out.OriginalEvent.Payload = strings.Replace(out.OriginalEvent.Payload, `"tenant":`, `"Tenant":`, 1)
				rehash = true
			case "failure-case-alias":
				out.OriginalEvent.Payload = strings.Replace(out.OriginalEvent.Payload, `"failure":`, `"Failure":`, 1)
				rehash = true
			}
			if rehash {
				out.OriginalEvent.Hash = crypt.Digest([]byte(out.OriginalEvent.PreviousHash + "\n" + out.OriginalEvent.Payload))
				out.Incident.EventHash = out.OriginalEvent.Hash
			}
			err := validateGoChecksumLegacyEvidence(tenant, out)
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if scenario == "overflow" {
				if !errors.Is(err, ErrMetadataLimit) {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrGoChecksumLegacyChanged) {
				t.Fatal("untrusted incident binding or label was accepted", scenario, err)
			}
		})
	}
}

func legacyReviewInput() GoChecksumLegacyReviewRequest {
	return GoChecksumLegacyReviewRequest{AcceptUnattributedHistory: true, IncidentHash: strings.Repeat("1", 64), KeyDigest: strings.Repeat("2", 64), CheckpointSHA256: strings.Repeat("3", 64), ReviewReferenceSHA256: strings.Repeat("4", 64), Reason: "Explicit separately reviewed external authority key"}
}

func TestGoChecksumRetainedConfigurationKeepsCreationGatedAndRequiresTrust(t *testing.T) {
	for _, scenario := range []string{"retained", "creation", "missing-authority", "unchecked", "unbounded-upstream", "different-format", "hosted"} {
		t.Run(scenario, func(t *testing.T) {
			a, _, _ := checksumPublicFixture(t)
			r := Repository{Name: "retained", Format: "go", Mode: "proxy", Settings: RepositorySettings{Upstream: &a.Endpoint, GoChecksumAuthority: &a, Cache: CacheSettings{RequireChecksum: true}}}
			switch scenario {
			case "missing-authority":
				r.Settings.GoChecksumAuthority = nil
			case "unchecked":
				r.Settings.Cache.RequireChecksum = false
			case "unbounded-upstream":
				r.Settings.Upstream = &upstream.Config{URL: "http://127.0.0.1:38443/"}
			case "different-format":
				r.Format = "generic"
			case "hosted":
				r.Mode = "hosted"
			}
			err := validateRepository(&r, scenario != "creation")
			if (scenario == "retained") != (err == nil) {
				t.Fatal("retained trust recovery changed creation/validation boundary", scenario, err)
			}
		})
	}
}

func TestGoChecksumLegacyReviewRequiresBoundedExplicitTrustBindings(t *testing.T) {
	for _, scenario := range []string{"apply", "preview", "ack", "zero-incident", "negative-incident", "repo", "source", "checkpoint", "incident-hash", "key-hash", "pin-hash", "review-hash", "empty-reason", "space-reason", "control-reason", "invalid-utf8", "large-reason", "exact-utf8-boundary"} {
		t.Run(scenario, func(t *testing.T) {
			input := legacyReviewInput()
			sequence := int64(7)
			repo := "source"
			switch scenario {
			case "preview":
				input.DryRun = true
				input.AcceptUnattributedHistory = false
			case "ack":
				input.AcceptUnattributedHistory = false
			case "zero-incident":
				sequence = 0
			case "negative-incident":
				sequence = -1
			case "repo":
				repo = "source/another"
			case "source":
				input.ExpectedSourceRevision = -1
			case "checkpoint":
				input.ExpectedCheckpointRevision = -1
			case "incident-hash":
				input.IncidentHash = strings.Repeat("A", 64)
			case "key-hash":
				input.KeyDigest = "short"
			case "pin-hash":
				input.CheckpointSHA256 = ""
			case "review-hash":
				input.ReviewReferenceSHA256 = strings.Repeat("a", 65)
			case "empty-reason":
				input.Reason = ""
			case "space-reason":
				input.Reason = "   "
			case "control-reason":
				input.Reason = "review\nreason"
			case "invalid-utf8":
				input.Reason = string([]byte{0xff})
			case "large-reason":
				input.Reason = strings.Repeat("é", 513)
			case "exact-utf8-boundary":
				input.Reason = strings.Repeat("é", 512)
			}
			err := validateGoChecksumLegacyReview(sequence, repo, input)
			valid := scenario == "apply" || scenario == "preview" || scenario == "exact-utf8-boundary"
			if (err == nil) != valid {
				t.Fatal("unbounded/implicit review binding", scenario, err)
			}
		})
	}
}

func FuzzGoChecksumLegacyEvidenceBindings(f *testing.F) {
	valid := legacyEvidenceFixture(f)
	if validateGoChecksumLegacyEvidence("legacy-team", valid) != nil {
		f.Fatal("valid journal fixture must verify in every worker")
	}
	f.Add([]byte(valid.OriginalEvent.Payload), int64(7), "legacy-team", valid.OriginalEvent.PreviousHash)
	f.Add([]byte(`{"kind":"proxy.retrieval.failed"}`), int64(1), "legacy-team", "")
	f.Fuzz(func(t *testing.T, payload []byte, sequence int64, tenant, previous string) {
		if len(payload) > MaxGoChecksumLegacyEvent+1 || len(tenant) > 128 || len(previous) > 128 {
			return
		}
		hash := crypt.Digest(append([]byte(previous+"\n"), payload...))
		out := GoChecksumLegacyEvidence{Incident: GoChecksumLegacyIncident{Sequence: sequence, EventHash: hash}, OriginalEvent: Event{Sequence: sequence, Payload: string(payload), PreviousHash: previous, Hash: hash}}
		if validateGoChecksumLegacyEvidence(tenant, out) != nil {
			return
		}
		var decoded map[string]any
		if json.Unmarshal(payload, &decoded) != nil || decoded["tenant"] != tenant || decoded["sequence"] != float64(sequence) || decoded["kind"] != "proxy.retrieval.failed" || sequence <= 0 || len(payload) > MaxGoChecksumLegacyEvent {
			t.Fatal("successful incident validation lost a retained binding")
		}
		data, ok := decoded["data"].(map[string]any)
		if !ok || data["failure"] != "upstream_checksum_fork" || out.Classification == "fork" {
			t.Fatal("a legacy label became proof")
		}
	})
}
