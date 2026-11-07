// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

// The shared session retains the selected-root manifest; this new receipt points
// at the complete graph parent and preserves the selection reference separately.
// A complete durable implementation must create both references atomically.
type GoRequirementExportSession struct {
	Profile string `json:"profile"`
	GoExportSetSession
	SelectionManifest blob.Object `json:"selection_manifest"`
	SourceCount       int         `json:"source_count"`
	MainGoMod         blob.Object `json:"main_go_mod"`
	RequirementProof  blob.Object `json:"requirement_proof"`
}

// Callers must first verify the complete original journal with the independent
// signer/head. A matching isolated event is neither a signature nor a permission,
// byte-verification, package/platform-closure or destination-admission result.
func BindGoRequirementExportManifest(raw []byte, tenant, id string, event crypt.JournalEvent) (GoRequirementExportManifest, error) {
	m, err := ParseGoRequirementExportManifest(raw)
	if err != nil || !ValidGoExportID(id) || m.Selection.Tenant != tenant || crypt.VerifyJournalEvent(tenant, event) != nil || m.Selection.ObservedJournal.Sequence >= event.Sequence {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	envelope, ok := checksumJournalObject([]byte(event.Payload), "tenant", "sequence", "kind", "data")
	if !ok || len(envelope) != 4 {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	var eventTenant, kind string
	var sequence int64
	if json.Unmarshal(envelope["tenant"], &eventTenant) != nil || eventTenant != tenant || json.Unmarshal(envelope["sequence"], &sequence) != nil || sequence != event.Sequence ||
		json.Unmarshal(envelope["kind"], &kind) != nil || kind != "go.requirement-export.created" {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	fields, ok := checksumJournalObject(envelope["data"], "profile", "id", "actor", "manifest", "root_count", "artifact_bytes", "state", "generation", "created_sequence", "change_sequence", "created_at", "changed_at", "expires_at", "max_expires_at", "server_time", "delivery_verified", "payload_pins_retained", "manifest_retained", "selection_manifest", "source_count", "main_go_mod", "requirement_proof")
	if !ok || len(fields) != 22 {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	for _, name := range []string{"manifest", "selection_manifest", "main_go_mod", "requirement_proof"} {
		object, ok := checksumJournalObject(fields[name], "digest", "size")
		if !ok || len(object) != 2 {
			return GoRequirementExportManifest{}, ErrGoRequirementExport
		}
	}
	selection, err := m.Selection.Bytes()
	if err != nil {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	var s GoRequirementExportSession
	if json.Unmarshal(envelope["data"], &s) != nil || s.Profile != GoRequirementExportProfile || s.ID != id || s.Actor == "" || len(s.Actor) > 256 || !utf8.ValidString(s.Actor) || strings.ContainsFunc(s.Actor, unicode.IsControl) ||
		s.Manifest != (blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}) || s.SelectionManifest != (blob.Object{Digest: crypt.Digest(selection), Size: int64(len(selection))}) ||
		s.MainGoMod != m.MainGoMod || s.RequirementProof != m.RequirementProof || s.SourceCount != len(m.Sources) || s.RootCount != len(m.Selection.Entries) || s.ArtifactBytes != m.Selection.DeclaredArtifactBytes ||
		s.State != "open" || s.Generation != 1 || s.CreatedSequence != event.Sequence || s.ChangeSequence != s.CreatedSequence || s.CreatedAt.Before(m.Selection.PreparedAt) || s.CreatedAt.Sub(m.Selection.PreparedAt) > 5*time.Minute ||
		!s.ChangedAt.Equal(s.CreatedAt) || s.ServerTime.Before(s.CreatedAt) || !s.ExpiresAt.After(s.ServerTime) || s.ExpiresAt.After(s.MaxExpiresAt) ||
		s.MaxExpiresAt.Sub(s.CreatedAt) != 24*time.Hour || s.DeliveryVerified || !s.PayloadPinsRetained || !s.ManifestRetained {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	return m, nil
}
