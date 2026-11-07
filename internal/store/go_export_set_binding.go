// SPDX-License-Identifier: BUSL-1.1
package store

import (
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"encoding/json"
	"time"
)

// Callers must first authenticate the complete journal against the separately
// selected external signer/head. A matching isolated event is not a signature,
// current admission, package-byte verification or complete dependency closure.
func BindGoExportSetManifest(raw []byte, tenant, id string, event crypt.JournalEvent) (GoExportSetManifest, error) {
	m, err := ParseGoExportSetManifest(raw)
	if err != nil || !ValidGoExportID(id) || m.Tenant != tenant || crypt.VerifyJournalEvent(tenant, event) != nil || m.ObservedJournal.Sequence >= event.Sequence {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	envelope, ok := checksumJournalObject([]byte(event.Payload), "tenant", "sequence", "kind", "data")
	if !ok {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	var eventTenant, kind string
	var sequence int64
	if json.Unmarshal(envelope["tenant"], &eventTenant) != nil || eventTenant != tenant || json.Unmarshal(envelope["sequence"], &sequence) != nil || sequence != event.Sequence || json.Unmarshal(envelope["kind"], &kind) != nil || kind != "go.export-set.created" {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	fields, ok := checksumJournalObject(envelope["data"], "id", "actor", "manifest", "root_count", "artifact_bytes", "state", "generation", "created_sequence", "change_sequence", "created_at", "changed_at", "expires_at", "max_expires_at", "server_time", "delivery_verified", "payload_pins_retained", "manifest_retained")
	if !ok || len(fields) != 17 {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	object, ok := checksumJournalObject(fields["manifest"], "digest", "size")
	if !ok || len(object) != 2 {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	var s GoExportSetSession
	if json.Unmarshal(envelope["data"], &s) != nil || s.ID != id || s.Actor == "" || len(s.Actor) > 256 || s.Manifest.Digest != crypt.Digest(raw) || s.Manifest.Size != int64(len(raw)) || s.RootCount != len(m.Entries) || s.ArtifactBytes != m.DeclaredArtifactBytes || s.State != "open" || s.Generation != 1 || s.CreatedSequence != event.Sequence || s.ChangeSequence != s.CreatedSequence || s.CreatedAt.Before(m.PreparedAt) || !s.ChangedAt.Equal(s.CreatedAt) || s.ServerTime.Before(s.CreatedAt) || !s.ExpiresAt.After(s.ServerTime) || s.ExpiresAt.After(s.MaxExpiresAt) || s.MaxExpiresAt.Sub(s.CreatedAt) != 24*time.Hour || s.DeliveryVerified || !s.PayloadPinsRetained || !s.ManifestRetained {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	return m, nil
}
