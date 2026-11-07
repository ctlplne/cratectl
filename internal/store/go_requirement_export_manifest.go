// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"golang.org/x/mod/semver"
)

const GoRequirementExportProfile = "cratectl.go.hosted.requirement-export.v1"
const MaxGoRequirementExportManifest = 16 << 20

var ErrGoRequirementExport = errors.New("invalid, incomplete or changed Go requirement export")

// Each descriptor binds both the original .mod and its complete source-policy
// manifest. Lower examined versions remain explicit even when not selected.
type GoRequirementExportSource struct {
	Repository     string      `json:"repository"`
	SourceRevision int64       `json:"source_revision"`
	Module         string      `json:"module"`
	Version        string      `json:"version"`
	Manifest       blob.Object `json:"manifest"`
	Mod            blob.Object `json:"mod"`
}

// This new format leaves the legacy explicit-set profile unchanged. It binds
// immutable metadata graph inputs; package/platform closure and all destination
// grants remain false. Durable creation/collection must stage and retain every
// referenced original before publishing or accepting this manifest.
type GoRequirementExportManifest struct {
	Profile          string                      `json:"profile"`
	Selection        GoExportSetManifest         `json:"selection"`
	MainGoMod        blob.Object                 `json:"main_go_mod"`
	RequirementProof blob.Object                 `json:"requirement_proof"`
	Sources          []GoRequirementExportSource `json:"sources"`
}

func requirementExportObject(o blob.Object, maximum int64) bool {
	return uploadDigest.MatchString(o.Digest) && o.Size > 0 && o.Size <= maximum
}

func requirementExportSourceOrder(a, b GoRequirementExportSource) int {
	if n := strings.Compare(a.Module, b.Module); n != 0 {
		return n
	}
	if n := semver.Compare(a.Version, b.Version); n != 0 {
		return n
	}
	return strings.Compare(a.Version, b.Version)
}

func (m GoRequirementExportManifest) Bytes() ([]byte, error) {
	if m.Profile != GoRequirementExportProfile || !requirementExportObject(m.MainGoMod, gomodule.MaxGoMod) ||
		!requirementExportObject(m.RequirementProof, gomodule.MaxRequirementProof) || len(m.Sources) < 1 || len(m.Sources) > gomodule.MaxRequirementProofSources {
		return nil, ErrGoRequirementExport
	}
	if _, err := m.Selection.Bytes(); err != nil {
		return nil, ErrGoRequirementExport
	}
	modBytes, manifestBytes := m.MainGoMod.Size, int64(0)
	byCoordinate := make(map[gomodule.Coordinate]GoRequirementExportSource, len(m.Sources))
	for n, s := range m.Sources {
		if _, err := gomodule.Canonical(s.Module, s.Version); err != nil || !Name.MatchString(s.Repository) || s.SourceRevision < 0 ||
			!requirementExportObject(s.Manifest, MaxGoExportManifest) || !requirementExportObject(s.Mod, gomodule.MaxGoMod) ||
			n > 0 && requirementExportSourceOrder(m.Sources[n-1], s) >= 0 ||
			s.Mod.Size > gomodule.DefaultGraphLimits().MetadataBytes-modBytes || s.Manifest.Size > maxGoExportPlanningMetadata-manifestBytes {
			return nil, ErrGoRequirementExport
		}
		modBytes += s.Mod.Size
		manifestBytes += s.Manifest.Size
		byCoordinate[gomodule.Coordinate{Module: s.Module, Version: s.Version}] = s
	}
	// The same exact version cannot be examined under one repository/epoch or
	// .mod identity while the selected native bytes come from another. A pruned
	// selected version may be absent from the examined set; its original payload
	// still belongs to the selection's independent physical-verification path.
	for _, root := range m.Selection.Entries {
		if source, ok := byCoordinate[gomodule.Coordinate{Module: root.Module, Version: root.Version}]; ok {
			if root.Repository != source.Repository || root.SourceRevision != source.SourceRevision ||
				root.Artifacts[1].Digest != source.Mod.Digest || root.Artifacts[1].Size != source.Mod.Size {
				return nil, ErrGoRequirementExport
			}
		}
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw)+1 > MaxGoRequirementExportManifest {
		return nil, ErrGoRequirementExport
	}
	return append(raw, '\n'), nil
}

// Bound the source array before allocating typed descriptors. Original source
// manifests and .mod data stay separate referenced files; neither is embedded.
func ParseGoRequirementExportManifest(raw []byte) (GoRequirementExportManifest, error) {
	if len(raw) < 1 || len(raw) > MaxGoRequirementExportManifest {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	var m GoRequirementExportManifest
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return GoRequirementExportManifest{}, ErrGoRequirementExport
		}
		seen[name] = true
		if name == "sources" {
			t, err = d.Token()
			if err != nil || t != json.Delim('[') {
				return GoRequirementExportManifest{}, ErrGoRequirementExport
			}
			for d.More() {
				if len(m.Sources) >= gomodule.MaxRequirementProofSources {
					return GoRequirementExportManifest{}, ErrGoRequirementExport
				}
				var item json.RawMessage
				if d.Decode(&item) != nil || len(item) > 4096 {
					return GoRequirementExportManifest{}, ErrGoRequirementExport
				}
				var source GoRequirementExportSource
				if json.Unmarshal(item, &source) != nil {
					return GoRequirementExportManifest{}, ErrGoRequirementExport
				}
				m.Sources = append(m.Sources, source)
			}
			t, err = d.Token()
			if err != nil || t != json.Delim(']') {
				return GoRequirementExportManifest{}, ErrGoRequirementExport
			}
			continue
		}
		if name == "selection" {
			var selection json.RawMessage
			if d.Decode(&selection) != nil || len(selection)+1 > MaxGoExportSetManifest {
				return GoRequirementExportManifest{}, ErrGoRequirementExport
			}
			m.Selection, err = ParseGoExportSetManifest(append(selection, '\n'))
			if err != nil {
				return GoRequirementExportManifest{}, ErrGoRequirementExport
			}
			continue
		}
		var target any
		switch name {
		case "profile":
			target = &m.Profile
		case "main_go_mod":
			target = &m.MainGoMod
		case "requirement_proof":
			target = &m.RequirementProof
		default:
			return GoRequirementExportManifest{}, ErrGoRequirementExport
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || len(value) > 4096 || json.Unmarshal(value, target) != nil {
			return GoRequirementExportManifest{}, ErrGoRequirementExport
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != 5 {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	if _, err = d.Token(); err != io.EOF {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	canonical, err := m.Bytes()
	if err != nil || !bytes.Equal(canonical, raw) {
		return GoRequirementExportManifest{}, ErrGoRequirementExport
	}
	return m, nil
}

// The caller must first authenticate and validate the parent. This per-source
// comparison performs bounded child work, avoiding a whole-parent reparse for
// each of up to1,024 inputs. It grants no signature/current-admission result.
func BindGoRequirementSourceManifest(parent GoRequirementExportManifest, ordinal int, raw []byte) (GoExportManifest, error) {
	if parent.Profile != GoRequirementExportProfile || ordinal < 0 || ordinal >= len(parent.Sources) || len(parent.Sources) > gomodule.MaxRequirementProofSources ||
		!Name.MatchString(parent.Selection.Tenant) || parent.Selection.PreparedAt.IsZero() || !parent.Selection.ObservedJournal.Valid() || parent.Selection.ObservedJournal.Tenant != parent.Selection.Tenant {
		return GoExportManifest{}, ErrGoRequirementExport
	}
	s := parent.Sources[ordinal]
	if !requirementExportObject(s.Manifest, MaxGoExportManifest) || int64(len(raw)) != s.Manifest.Size || crypt.Digest(raw) != s.Manifest.Digest {
		return GoExportManifest{}, ErrGoRequirementExport
	}
	m, err := ParseGoExportManifest(raw)
	if err != nil || m.Tenant != parent.Selection.Tenant || m.Repository != s.Repository || m.Module != s.Module || m.Version != s.Version || m.SourceRevision != s.SourceRevision ||
		!m.PreparedAt.Equal(parent.Selection.PreparedAt) || m.ObservedJournal != parent.Selection.ObservedJournal || len(m.Artifacts) != 3 ||
		m.Artifacts[1].Digest != s.Mod.Digest || m.Artifacts[1].Size != s.Mod.Size {
		return GoExportManifest{}, ErrGoRequirementExport
	}
	return m, nil
}

// Check the authenticated index's references and selected physical source set
// against the authenticated parent before independently replaying original bytes
// with gomodule.VerifyRequirementProof. This does not replace that replay.
func BindGoRequirementProof(parent GoRequirementExportManifest, raw []byte) (gomodule.RequirementProof, error) {
	if parent.Profile != GoRequirementExportProfile || !requirementExportObject(parent.RequirementProof, gomodule.MaxRequirementProof) ||
		int64(len(raw)) != parent.RequirementProof.Size || crypt.Digest(raw) != parent.RequirementProof.Digest {
		return gomodule.RequirementProof{}, ErrGoRequirementExport
	}
	p, err := gomodule.ParseRequirementProof(raw)
	if err != nil || p.Main.SHA256 != parent.MainGoMod.Digest || p.Main.Size != parent.MainGoMod.Size || len(p.Sources) != len(parent.Sources) || len(p.Selected) != len(parent.Selection.Entries) {
		return gomodule.RequirementProof{}, ErrGoRequirementExport
	}
	for n, s := range p.Sources {
		w := parent.Sources[n]
		if s.Module != w.Module || s.Version != w.Version || s.Mod.SHA256 != w.Mod.Digest || s.Mod.Size != w.Mod.Size {
			return gomodule.RequirementProof{}, ErrGoRequirementExport
		}
	}
	for n, s := range p.Selected {
		root := parent.Selection.Entries[n]
		if s.SourceModule != root.Module || s.SourceVersion != root.Version {
			return gomodule.RequirementProof{}, ErrGoRequirementExport
		}
	}
	return p, nil
}
