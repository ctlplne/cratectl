// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

const GoExportProfile = "cratectl.go.hosted.export.v1"
const MaxGoExportManifest = 32 << 10

var ErrGoExportInput = errors.New("invalid bounded hosted Go export request")
var ErrGoExportChanged = errors.New("export snapshot or generation changed")
var ErrGoExportExpired = errors.New("export session expired or cancelled")
var ErrGoExportLimit = errors.New("active export session budget exceeded")

type GoExportArtifact struct {
	Path            string          `json:"path"`
	Digest          string          `json:"digest"`
	Size            int64           `json:"size"`
	MediaType       string          `json:"media_type"`
	Metadata        json.RawMessage `json:"metadata"`
	CreatedAt       time.Time       `json:"created_at"`
	SourceRevision  int64           `json:"source_revision"`
	Decision        string          `json:"decision"`
	DecisionVersion int64           `json:"decision_version"`
	Lifecycle       ArtifactState   `json:"lifecycle"`
}

// This is historical source policy, never a destination permission, scan result,
// SumDB grant, dependency closure or authority to serve a future request.
type GoExportManifest struct {
	Profile                  string              `json:"profile"`
	Tenant                   string              `json:"tenant"`
	Repository               string              `json:"repository"`
	Module                   string              `json:"module"`
	Version                  string              `json:"version"`
	SourceRevision           int64               `json:"source_revision"`
	RequireReview            bool                `json:"require_review"`
	Access                   string              `json:"access"`
	PreparedAt               time.Time           `json:"prepared_at"`
	ObservedJournal          crypt.JournalAnchor `json:"observed_journal"`
	Artifacts                []GoExportArtifact  `json:"artifacts"`
	PolicyScope              string              `json:"policy_scope"`
	CurrentRegistryAdmission bool                `json:"current_registry_admission"`
	ChecksumAuthority        bool                `json:"checksum_authority_verified"`
	DependencyClosure        bool                `json:"dependency_closure"`
}

func (m GoExportManifest) validate() error {
	c, err := gomodule.Canonical(m.Module, m.Version)
	if err != nil || m.Profile != GoExportProfile || !Name.MatchString(m.Tenant) || !Name.MatchString(m.Repository) || m.SourceRevision < 0 || (m.Access != "tenant" && m.Access != "restricted") || m.PreparedAt.IsZero() || !m.ObservedJournal.Valid() || m.ObservedJournal.Tenant != m.Tenant || len(m.Artifacts) != 3 || m.PolicyScope != "historical source decisions; not destination admission" || m.CurrentRegistryAdmission || m.ChecksumAuthority || m.DependencyClosure {
		return ErrGoExportInput
	}
	limits := [3]int64{512 << 20, gomodule.MaxGoMod, gomodule.MaxVersionInfo}
	as := make([]Artifact, 0, 3)
	for n, kind := range []string{"zip", "mod", "info"} {
		a := m.Artifacts[n]
		if a.Path != c.Prefix()+"."+kind || !uploadDigest.MatchString(a.Digest) || a.Size < 0 || a.Size > limits[n] || a.MediaType != goMedia[kind] || len(a.Metadata) > MaxGoModuleMetadata || a.CreatedAt.IsZero() || a.SourceRevision < 0 || a.DecisionVersion < 0 || a.Decision != "allowed" && a.Decision != "unassessed" || m.RequireReview && a.Decision != "allowed" || a.Lifecycle.Repository != m.Repository || a.Lifecycle.Path != a.Path || a.Lifecycle.Deleted || a.Lifecycle.Revision < 0 || a.Lifecycle.Digest != "" && a.Lifecycle.Digest != a.Digest || len(a.Lifecycle.Actor) > 256 || !validLifecycleReason(a.Lifecycle.Reason) || !validLifecycleReason(a.Lifecycle.HoldReason) {
			return ErrGoExportInput
		}
		as = append(as, Artifact{Path: a.Path, Digest: a.Digest, Size: a.Size, MediaType: a.MediaType, Metadata: a.Metadata})
	}
	if _, err := validateGoModuleBundle(as); err != nil {
		return ErrGoExportInput
	}
	return nil
}

func (m GoExportManifest) Bytes() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw)+1 > MaxGoExportManifest {
		return nil, ErrGoExportInput
	}
	return append(raw, '\n'), nil
}

func ParseGoExportManifest(raw []byte) (GoExportManifest, error) {
	var m GoExportManifest
	if len(raw) == 0 || len(raw) > MaxGoExportManifest || json.Unmarshal(raw, &m) != nil {
		return GoExportManifest{}, ErrGoExportInput
	}
	canonical, err := m.Bytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		return GoExportManifest{}, ErrGoExportInput
	}
	return m, nil
}

func (m GoExportManifest) Publication() GoHostedPublication {
	if m.validate() != nil {
		return GoHostedPublication{}
	}
	return GoHostedPublication{m.Tenant, m.Repository, gomodule.Coordinate{Module: m.Module, Version: m.Version}, m.Artifacts[0].Digest, m.Artifacts[1].Digest, m.Artifacts[2].Digest}
}

// As with the original publication binding, the caller must first authenticate
// the complete journal and external checkpoint. The isolated event is not trust.
func BindGoExportManifest(raw []byte, tenant, repository, id string, c gomodule.Coordinate, event crypt.JournalEvent) (GoExportManifest, error) {
	m, err := ParseGoExportManifest(raw)
	if err != nil || !uploadDigest.MatchString(id) || m.Tenant != tenant || m.Repository != repository || m.Module != c.Module || m.Version != c.Version || crypt.VerifyJournalEvent(tenant, event) != nil {
		return GoExportManifest{}, ErrGoExportInput
	}
	envelope, ok := checksumJournalObject([]byte(event.Payload), "tenant", "sequence", "kind", "data")
	if !ok {
		return GoExportManifest{}, ErrGoExportInput
	}
	var originalTenant, kind string
	var seq int64
	if json.Unmarshal(envelope["tenant"], &originalTenant) != nil || originalTenant != tenant || json.Unmarshal(envelope["sequence"], &seq) != nil || seq != event.Sequence || json.Unmarshal(envelope["kind"], &kind) != nil || kind != "go.export.created" {
		return GoExportManifest{}, ErrGoExportInput
	}
	data, ok := checksumJournalObject(envelope["data"], "id", "repository", "module", "version", "source_revision", "manifest", "created_sequence")
	if !ok {
		return GoExportManifest{}, ErrGoExportInput
	}
	var gotID, repo, module, version string
	var source, created int64
	if json.Unmarshal(data["id"], &gotID) != nil || gotID != id || json.Unmarshal(data["repository"], &repo) != nil || repo != repository || json.Unmarshal(data["module"], &module) != nil || module != c.Module || json.Unmarshal(data["version"], &version) != nil || version != c.Version || json.Unmarshal(data["source_revision"], &source) != nil || source != m.SourceRevision || json.Unmarshal(data["created_sequence"], &created) != nil || created != seq {
		return GoExportManifest{}, ErrGoExportInput
	}
	object, ok := checksumJournalObject(data["manifest"], "digest", "size")
	if !ok || len(object) != 2 {
		return GoExportManifest{}, ErrGoExportInput
	}
	var expected blob.Object
	if json.Unmarshal(object["digest"], &expected.Digest) != nil || json.Unmarshal(object["size"], &expected.Size) != nil || expected.Digest != crypt.Digest(raw) || expected.Size != int64(len(raw)) {
		return GoExportManifest{}, ErrGoExportInput
	}
	return m, nil
}
