// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func checksumJournalFixture(t testing.TB, unverified bool) ([]byte, GoChecksumFailureRecord, crypt.JournalEvent) {
	t.Helper()
	_, record := checksumFailureRecord(t)
	failure := "upstream_checksum_fork"
	if unverified {
		record.Classification = "unverified"
		record.Report.Attempts = []GoChecksumFailureAttempt{{Path: "/lookup/owned", Status: 503, Code: "status"}}
		failure = "upstream_checksum_unverified"
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"tenant": record.Tenant, "sequence": 7, "kind": "proxy.retrieval.failed", "actor": "operator", "data": map[string]any{"repository": record.Repository, "path": record.RootPath, "generation": record.Generation, "source_revision": record.SourceRevision, "state": "failed", "failure": failure, "go_checksum_failure_digest": crypt.Digest(raw), "upstream_status": 503}})
	if err != nil {
		t.Fatal(err)
	}
	event := crypt.JournalEvent{Sequence: 7, Payload: string(payload), PreviousHash: strings.Repeat("b", 64)}
	event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
	return raw, record, event
}

func TestGoChecksumJournalBindingRequiresOriginalExactTypedFailureIdentity(t *testing.T) {
	for _, scenario := range []string{"fork", "unverified", "extra-metadata", "wrong-tenant", "wrong-repository", "wrong-path", "wrong-generation", "wrong-source", "wrong-state", "wrong-kind", "wrong-classification", "wrong-digest", "missing-digest", "null-source", "duplicate-data", "data-alias", "envelope-alias", "duplicate-envelope", "bad-link", "changed-body", "noncanonical-record", "record-mismatch", "oversized-record", "legacy-label"} {
		t.Run(scenario, func(t *testing.T) {
			raw, record, event := checksumJournalFixture(t, scenario == "unverified")
			rehash := true
			switch scenario {
			case "extra-metadata":
				event.Payload = strings.Replace(event.Payload, `"upstream_status":503`, `"upstream_status":503,"unknown_metadata":{"claim":"not authenticated truth"}`, 1)
			case "wrong-tenant":
				record.Tenant = "another-team"
			case "wrong-repository":
				event.Payload = strings.Replace(event.Payload, `"repository":"owned"`, `"repository":"other"`, 1)
			case "wrong-path":
				event.Payload = strings.Replace(event.Payload, record.RootPath, record.RootPath+"changed", 1)
			case "wrong-generation":
				event.Payload = strings.Replace(event.Payload, `"generation":2`, `"generation":3`, 1)
			case "wrong-source":
				event.Payload = strings.Replace(event.Payload, `"source_revision":0`, `"source_revision":1`, 1)
			case "wrong-state":
				event.Payload = strings.Replace(event.Payload, `"state":"failed"`, `"state":"ready"`, 1)
			case "wrong-kind":
				event.Payload = strings.Replace(event.Payload, "proxy.retrieval.failed", "proxy.retrieval.ready", 1)
			case "wrong-classification":
				event.Payload = strings.Replace(event.Payload, "upstream_checksum_fork", "upstream_checksum_unverified", 1)
			case "wrong-digest":
				event.Payload = strings.Replace(event.Payload, crypt.Digest(raw), strings.Repeat("a", 64), 1)
			case "missing-digest":
				event.Payload = strings.Replace(event.Payload, `"go_checksum_failure_digest":"`+crypt.Digest(raw)+`",`, "", 1)
			case "legacy-label":
				event.Payload = `{"tenant":"` + record.Tenant + `","sequence":7,"kind":"proxy.retrieval.failed","data":{"failure":"upstream_checksum_fork","repository":"owned","path":"` + record.RootPath + `"}}`
			case "null-source":
				event.Payload = strings.Replace(event.Payload, `"source_revision":0`, `"source_revision":null`, 1)
			case "duplicate-data":
				event.Payload = strings.Replace(event.Payload, `"generation":2`, `"generation":2,"generation":2`, 1)
			case "data-alias":
				event.Payload = strings.Replace(event.Payload, `"generation":2`, `"generation":2,"Generation":2`, 1)
			case "envelope-alias":
				event.Payload = strings.Replace(event.Payload, `"tenant":"`+record.Tenant+`"`, `"tenant":"`+record.Tenant+`","Tenant":"`+record.Tenant+`"`, 1)
			case "duplicate-envelope":
				event.Payload = strings.Replace(event.Payload, `"sequence":7`, `"sequence":7,"sequence":7`, 1)
			case "bad-link":
				event.Hash = strings.Repeat("c", 64)
				rehash = false
			case "changed-body":
				event.Payload += " "
				rehash = false
			case "noncanonical-record":
				raw = append(raw, '\n')
			case "record-mismatch":
				record.Generation++
			case "oversized-record":
				raw = bytes.Repeat([]byte("x"), MaxGoChecksumFailureEvidence+1)
			}
			if rehash {
				event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
			}
			digest, err := BindGoChecksumFailureJournalEvent(raw, record, event)
			valid := scenario == "fork" || scenario == "unverified" || scenario == "extra-metadata"
			if valid {
				if err != nil || digest != crypt.Digest(raw) {
					t.Fatal("exact original typed binding refused", scenario, err)
				}
			} else if !errors.Is(err, ErrGoModuleUnvalidated) || digest != "" {
				t.Fatal("unattributed or mismatched failure produced a digest", scenario, err)
			}
		})
	}
}

func FuzzGoChecksumJournalBindings(f *testing.F) {
	raw, record, event := checksumJournalFixture(f, false)
	f.Add(event.Payload)
	f.Add(`{"tenant":"failure-team","sequence":7,"kind":"proxy.retrieval.failed","data":{"failure":"upstream_checksum_fork"}}`)
	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > 64<<10 {
			return
		}
		selected := event
		selected.Payload = payload
		selected.Hash = crypt.Digest([]byte(selected.PreviousHash + "\n" + payload))
		digest, err := BindGoChecksumFailureJournalEvent(raw, record, selected)
		if err != nil {
			if digest != "" {
				t.Fatal("invalid binding returned a digest")
			}
			return
		}
		if digest != crypt.Digest(raw) || crypt.VerifyJournalEvent(record.Tenant, selected) != nil {
			t.Fatal("unbound failure digest accepted")
		}
	})
}
