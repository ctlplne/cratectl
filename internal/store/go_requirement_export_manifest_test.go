// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func requirementExportManifestFixture(t testing.TB) (GoRequirementExportManifest, []byte) {
	t.Helper()
	selection := exportSetManifestFixture(t, 1)
	input := selection.Entries[0]
	raw, err := input.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m := GoRequirementExportManifest{Profile: GoRequirementExportProfile, Selection: selection,
		MainGoMod: blob.Object{Digest: strings.Repeat("a", 64), Size: 17}, RequirementProof: blob.Object{Digest: strings.Repeat("b", 64), Size: 27},
		Sources: []GoRequirementExportSource{{Repository: input.Repository, SourceRevision: input.SourceRevision, Module: input.Module, Version: input.Version,
			Manifest: blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}, Mod: blob.Object{Digest: input.Artifacts[1].Digest, Size: input.Artifacts[1].Size}}}}
	return m, raw
}

func TestGoRequirementExportManifestRetainsCanonicalSeparateReferences(t *testing.T) {
	m, source := requirementExportManifestFixture(t)
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGoRequirementExportManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := parsed.Bytes()
	if err != nil || !bytes.Equal(raw, repeated) || parsed.Selection.DependencyClosure || parsed.Selection.ChecksumAuthority || parsed.Selection.CurrentRegistryAdmission {
		t.Fatal("reference-only parent changed its bytes or grants", err)
	}
	input, err := BindGoRequirementSourceManifest(parsed, 0, source)
	if err != nil || input.Module != m.Sources[0].Module || input.ObservedJournal != m.Selection.ObservedJournal {
		t.Fatal("original source manifest not bound to the common observation", err)
	}
	if _, err := ParseGoExportSetManifest(raw); err == nil {
		t.Fatal("legacy explicit-set parser accepted the new graph format")
	}
}

func TestGoRequirementExportManifestRefusesDifferentSelectedAndExaminedAuthority(t *testing.T) {
	for _, scenario := range []string{"repository", "source-revision", "mod-digest", "mod-size"} {
		t.Run(scenario, func(t *testing.T) {
			m, _ := requirementExportManifestFixture(t)
			switch scenario {
			case "repository":
				m.Sources[0].Repository = "other"
			case "source-revision":
				m.Sources[0].SourceRevision++
			case "mod-digest":
				m.Sources[0].Mod.Digest = strings.Repeat("f", 64)
			case "mod-size":
				m.Sources[0].Mod.Size++
			}
			if raw, err := m.Bytes(); err == nil || raw != nil {
				t.Fatal("selected bytes and examined graph input came from different source authority", scenario)
			}
		})
	}
}

func TestGoRequirementExportSourceRefusesChangedOrMixedObservation(t *testing.T) {
	for _, scenario := range []string{"bytes", "size", "tenant", "time", "head", "epoch", "coordinate", "mod", "ordinal"} {
		t.Run(scenario, func(t *testing.T) {
			m, raw := requirementExportManifestFixture(t)
			ordinal := 0
			switch scenario {
			case "bytes":
				raw = bytes.Replace(raw, []byte(`"owned"`), []byte(`"other"`), 1)
			case "size":
				m.Sources[0].Manifest.Size++
			case "tenant":
				m.Selection.Tenant = "other-team"
			case "time":
				m.Selection.PreparedAt = m.Selection.PreparedAt.Add(time.Second)
			case "head":
				m.Selection.ObservedJournal.Sequence = 1
				m.Selection.ObservedJournal.Hash = strings.Repeat("c", 64)
			case "epoch":
				m.Sources[0].SourceRevision++
			case "coordinate":
				m.Sources[0].Version = "v1.9.0"
			case "mod":
				m.Sources[0].Mod.Digest = strings.Repeat("f", 64)
			case "ordinal":
				ordinal = -1
			}
			got, err := BindGoRequirementSourceManifest(m, ordinal, raw)
			if err == nil || len(got.Artifacts) != 0 {
				t.Fatal("changed source returned a partial/success result", scenario)
			}
		})
	}
}

func TestGoRequirementExportManifestRefusesAmbiguousOrOverBudgetInput(t *testing.T) {
	m, _ := requirementExportManifestFixture(t)
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{nil, []byte("null"), append(bytes.Clone(raw), '\n'),
		bytes.Replace(raw, []byte(`"profile":`), []byte(`"profile":"duplicate","profile":`), 1),
		bytes.Replace(raw, []byte(`"sources":`), []byte(`"Sources":`), 1),
		bytes.Replace(raw, []byte(`"main_go_mod":`), []byte(`"dependency_closure":true,"main_go_mod":`), 1),
		bytes.Replace(raw, []byte(`"mod":`), []byte(`"unknown":true,"mod":`), 1),
		[]byte(`{"sources":[` + strings.Repeat(`{},`, gomodule.MaxRequirementProofSources) + `{}]}`),
		[]byte(strings.Repeat(" ", MaxGoRequirementExportManifest+1))} {
		if _, err := ParseGoRequirementExportManifest(body); err == nil {
			t.Fatal("ambiguous or over-budget reference manifest accepted")
		}
	}
	for _, scenario := range []string{"main", "proof", "duplicate", "negative-epoch", "source-count", "authority"} {
		m, _ := requirementExportManifestFixture(t)
		switch scenario {
		case "main":
			m.MainGoMod.Size = gomodule.MaxGoMod + 1
		case "proof":
			m.RequirementProof.Size = gomodule.MaxRequirementProof + 1
		case "duplicate":
			m.Sources = append(m.Sources, m.Sources[0])
		case "negative-epoch":
			m.Sources[0].SourceRevision = -1
		case "source-count":
			m.Sources = make([]GoRequirementExportSource, gomodule.MaxRequirementProofSources+1)
		case "authority":
			m.Selection.ChecksumAuthority = true
		}
		if raw, err := m.Bytes(); err == nil || raw != nil {
			t.Fatal("invalid manifest returned bytes", scenario)
		}
	}
}

func TestGoRequirementProofReferencesBindSelectedRootsAndEveryExaminedSource(t *testing.T) {
	m, _ := requirementExportManifestFixture(t)
	root := m.Selection.Entries[0]
	p := gomodule.RequirementProof{Profile: gomodule.RequirementProofProfile,
		Main: gomodule.RequirementObject{SHA256: m.MainGoMod.Digest, Size: m.MainGoMod.Size},
		Sources: []gomodule.RequirementSource{{Module: m.Sources[0].Module, Version: m.Sources[0].Version,
			Mod: gomodule.RequirementObject{SHA256: m.Sources[0].Mod.Digest, Size: m.Sources[0].Mod.Size}}},
		Selected: []gomodule.RequirementSelection{{Module: root.Module, Version: root.Version, SourceModule: root.Module, SourceVersion: root.Version}}}
	raw, err := p.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m.RequirementProof = blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}
	if _, err := BindGoRequirementProof(m, raw); err != nil {
		t.Fatal("matching index references refused", err)
	}
	m.Sources[0].Mod.Size++
	if _, err := BindGoRequirementProof(m, raw); err == nil {
		t.Fatal("different source index accepted")
	}
	m, _ = requirementExportManifestFixture(t)
	m.RequirementProof = blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}
	m.Selection.Entries[0].Version = "v1.9.0"
	if _, err := BindGoRequirementProof(m, raw); err == nil {
		t.Fatal("index selection differs from signed parent roots")
	}
	// Fields that merely claim a signature or grant must not enter the format.
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("owned canonical index")
	}
	value["signature_verified"] = true
	changed, _ := json.Marshal(value)
	if _, err := BindGoRequirementProof(m, append(changed, '\n')); err == nil {
		t.Fatal("unreviewed signature-shaped field accepted")
	}
}

func FuzzGoRequirementExportManifest(f *testing.F) {
	m, _ := requirementExportManifestFixture(f)
	raw, err := m.Bytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("null"))
	f.Add([]byte(`{"sources":[{}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		m, err := ParseGoRequirementExportManifest(raw)
		if err != nil {
			if m.Profile != "" || len(m.Sources) != 0 {
				t.Fatal("failed parent returned partial metadata")
			}
			return
		}
		canonical, err := m.Bytes()
		if err != nil || !bytes.Equal(canonical, raw) || len(m.Sources) > gomodule.MaxRequirementProofSources ||
			m.Selection.DependencyClosure || m.Selection.ChecksumAuthority || m.Selection.CurrentRegistryAdmission {
			t.Fatal("canonical parent changed its bytes, budgets or grants")
		}
	})
}
