// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func goExportSetBindingFixture(t testing.TB) ([]byte, string, crypt.JournalEvent) {
	t.Helper()
	m := exportSetManifestFixture(t, 2)
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 64)
	s := GoExportSetSession{ID: id, Actor: "owned", Manifest: (GoExportSetPlan{raw: raw}).Object(), RootCount: 2, ArtifactBytes: m.DeclaredArtifactBytes, State: "open", Generation: 1, CreatedSequence: 7, ChangeSequence: 7, CreatedAt: m.PreparedAt.Add(time.Second), ChangedAt: m.PreparedAt.Add(time.Second), ExpiresAt: m.PreparedAt.Add(time.Minute), MaxExpiresAt: m.PreparedAt.Add(time.Second + 24*time.Hour), ServerTime: m.PreparedAt.Add(2 * time.Second), PayloadPinsRetained: true, ManifestRetained: true}
	payload, _ := json.Marshal(map[string]any{"tenant": m.Tenant, "kind": "go.export-set.created", "sequence": 7, "data": s})
	e := crypt.JournalEvent{Sequence: 7, Payload: string(payload), PreviousHash: strings.Repeat("e", 64)}
	e.Hash = crypt.Digest([]byte(e.PreviousHash + "\n" + e.Payload))
	return raw, id, e
}
func TestGoExportSetBindingRequiresExactOriginalCreationAndCanonicalWholeManifest(t *testing.T) {
	for _, scenario := range []string{"original", "wrong-tenant", "wrong-id", "wrong-event-hash", "changed-late-member", "wrong-kind", "duplicate-kind", "null-root-count", "root-count", "byte-total", "manifest-digest", "manifest-size", "generation", "state", "created-sequence", "change-sequence", "delivery-claim", "missing-pins", "missing-manifest-retention", "prepared-after-created", "wrong-change-time", "expired-at-create", "overlong-window", "unknown-session-field", "alias-session-field", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			raw, id, event := goExportSetBindingFixture(t)
			tenant := "export-team"
			var envelope map[string]json.RawMessage
			_ = json.Unmarshal([]byte(event.Payload), &envelope)
			var s GoExportSetSession
			_ = json.Unmarshal(envelope["data"], &s)
			switch scenario {
			case "wrong-tenant":
				tenant = "other-team"
			case "wrong-id":
				id = strings.Repeat("d", 64)
			case "wrong-event-hash":
				event.Hash = strings.Repeat("a", 64)
			case "changed-late-member":
				m, err := ParseGoExportSetManifest(raw)
				if err != nil {
					t.Fatal(err)
				}
				m.Entries[1].Artifacts[0].DecisionVersion++
				raw, err = m.Bytes()
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-kind":
				envelope["kind"] = json.RawMessage(`"go.export-set.changed"`)
			case "root-count":
				s.RootCount--
			case "byte-total":
				s.ArtifactBytes++
			case "manifest-digest":
				s.Manifest.Digest = strings.Repeat("b", 64)
			case "manifest-size":
				s.Manifest.Size++
			case "generation":
				s.Generation++
			case "state":
				s.State = "acknowledged"
			case "created-sequence":
				s.CreatedSequence++
			case "change-sequence":
				s.ChangeSequence++
			case "delivery-claim":
				s.DeliveryVerified = true
			case "missing-pins":
				s.PayloadPinsRetained = false
			case "missing-manifest-retention":
				s.ManifestRetained = false
			case "prepared-after-created":
				s.CreatedAt = s.CreatedAt.Add(-time.Hour)
			case "wrong-change-time":
				s.ChangedAt = s.ChangedAt.Add(time.Second)
			case "expired-at-create":
				s.ExpiresAt = s.ServerTime
			case "overlong-window":
				s.MaxExpiresAt = s.MaxExpiresAt.Add(time.Second)
			case "trailing":
				raw = append(raw, []byte("{}\n")...)
			}
			if scenario != "wrong-event-hash" {
				data, _ := json.Marshal(s)
				switch scenario {
				case "unknown-session-field":
					data = bytes.Replace(data, []byte(`"id":`), []byte(`"extra":true,"id":`), 1)
				case "alias-session-field":
					data = bytes.Replace(data, []byte(`"root_count":`), []byte(`"Root_Count":`), 1)
				case "null-root-count":
					data = bytes.Replace(data, []byte(`"root_count":2`), []byte(`"root_count":null`), 1)
				}
				envelope["data"] = data
				payload, _ := json.Marshal(envelope)
				if scenario == "duplicate-kind" {
					payload = bytes.Replace(payload, []byte(`"kind":`), []byte(`"kind":"go.export-set.created","kind":`), 1)
				}
				event.Payload = string(payload)
				event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
			}
			got, err := BindGoExportSetManifest(raw, tenant, id, event)
			if scenario == "original" {
				if err != nil || len(got.Entries) != 2 {
					t.Fatal("original common creation refused", err)
				}
			} else if err == nil || len(got.Entries) != 0 {
				t.Fatal("changed original returned partial binding", scenario, err)
			}
		})
	}
}
func FuzzGoExportSetManifestBinding(f *testing.F) {
	raw, id, event := goExportSetBindingFixture(f)
	f.Add(raw, []byte(event.Payload))
	f.Add([]byte("null"), []byte("{}"))
	f.Fuzz(func(t *testing.T, manifest, payload []byte) {
		if len(manifest) > MaxGoExportSetManifest || len(payload) > crypt.MaxJournalPayload {
			return
		}
		e := event
		e.Payload = string(payload)
		e.Hash = crypt.Digest([]byte(e.PreviousHash + "\n" + e.Payload))
		m, err := BindGoExportSetManifest(manifest, "export-team", id, e)
		if err != nil {
			if len(m.Entries) != 0 {
				t.Fatal("failed binding returned roots")
			}
			return
		}
		canonical, err := m.Bytes()
		if err != nil || !bytes.Equal(canonical, manifest) {
			t.Fatal("bound noncanonical common manifest", err)
		}
	})
}
