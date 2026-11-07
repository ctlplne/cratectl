// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestGoRequirementExportBindsExactOriginalCreationAndAllMetadataReferences(t *testing.T) {
	for _, scenario := range []string{"original", "parent", "selection", "main", "proof", "sources", "root-count", "closure-shaped-field", "kind", "renewal", "tenant", "sequence", "delivery", "actor-control", "stale-creation", "missing-envelope-actor", "wrong-envelope-actor", "missing-envelope-time", "invalid-envelope-time", "unknown-envelope-field", "minimal-envelope"} {
		t.Run(scenario, func(t *testing.T) {
			m, _ := requirementExportManifestFixture(t)
			raw, err := m.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			selected, err := m.Selection.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			now := m.Selection.PreparedAt.Add(time.Second)
			id := strings.Repeat("d", 64)
			s := GoRequirementExportSession{Profile: GoRequirementExportProfile, GoExportSetSession: GoExportSetSession{ID: id, Actor: "operator",
				Manifest: blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}, RootCount: len(m.Selection.Entries), ArtifactBytes: m.Selection.DeclaredArtifactBytes,
				State: "open", Generation: 1, CreatedSequence: 7, ChangeSequence: 7, CreatedAt: now, ChangedAt: now, ServerTime: now, ExpiresAt: now.Add(time.Hour), MaxExpiresAt: now.Add(24 * time.Hour), PayloadPinsRetained: true, ManifestRetained: true},
				SelectionManifest: blob.Object{Digest: crypt.Digest(selected), Size: int64(len(selected))}, SourceCount: len(m.Sources), MainGoMod: m.MainGoMod, RequirementProof: m.RequirementProof}
			kind, tenant := "go.requirement-export.created", m.Selection.Tenant
			switch scenario {
			case "parent":
				s.Manifest.Digest = strings.Repeat("f", 64)
			case "selection":
				s.SelectionManifest.Digest = strings.Repeat("f", 64)
			case "main":
				s.MainGoMod.Size++
			case "proof":
				s.RequirementProof.Digest = strings.Repeat("f", 64)
			case "sources":
				s.SourceCount++
			case "root-count":
				s.RootCount++
			case "kind":
				kind = "go.export-set.created"
			case "renewal":
				s.Generation = 2
				s.ChangeSequence = 8
			case "tenant":
				tenant = "other-team"
			case "sequence":
				s.CreatedSequence = 6
			case "delivery":
				s.DeliveryVerified = true
			case "actor-control":
				s.Actor = "operator\n"
			case "stale-creation":
				s.CreatedAt = m.Selection.PreparedAt.Add(6 * time.Minute)
				s.ChangedAt, s.ServerTime = s.CreatedAt, s.CreatedAt
				s.ExpiresAt, s.MaxExpiresAt = s.CreatedAt.Add(time.Hour), s.CreatedAt.Add(24*time.Hour)
			}
			data, _ := json.Marshal(s)
			if scenario == "closure-shaped-field" {
				var value map[string]any
				json.Unmarshal(data, &value)
				value["dependency_closure"] = true
				data, _ = json.Marshal(value)
			}
			// appendEventIntent emits these six original envelope fields. A
			// synthetic four-field event is not the production creation shape.
			envelope := map[string]any{"tenant": tenant, "sequence": 7, "kind": kind, "actor": s.Actor, "time": now.UTC().Format(time.RFC3339Nano), "data": json.RawMessage(data)}
			switch scenario {
			case "missing-envelope-actor":
				delete(envelope, "actor")
			case "wrong-envelope-actor":
				envelope["actor"] = "another-operator"
			case "missing-envelope-time":
				delete(envelope, "time")
			case "invalid-envelope-time":
				envelope["time"] = "yesterday"
			case "unknown-envelope-field":
				envelope["delivery_verified"] = true
			case "minimal-envelope":
				delete(envelope, "actor")
				delete(envelope, "time")
			}
			payload, _ := json.Marshal(envelope)
			event := crypt.JournalEvent{Sequence: 7, PreviousHash: strings.Repeat("e", 64), Payload: string(payload)}
			event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
			bound, err := BindGoRequirementExportManifest(raw, m.Selection.Tenant, id, event)
			if scenario == "original" {
				if err != nil || bound.Profile != m.Profile || bound.Selection.DependencyClosure {
					t.Fatal("owned original metadata binding", err)
				}
			} else if err == nil || bound.Profile != "" {
				t.Fatal("changed or later event granted an original graph result", scenario, err)
			}
		})
	}
}
