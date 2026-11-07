// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

type GoRequirementExportRequest struct {
	Repository             string `json:"repository"`
	ExpectedSourceRevision int64  `json:"expected_source_revision"`
	MainGoMod              string `json:"main_go_mod"`
	LifetimeSeconds        int    `json:"lifetime_seconds"`
	MaxArtifactBytes       int64  `json:"max_artifact_bytes"`
}

func (r GoRequirementExportRequest) Validate() error {
	if !Name.MatchString(r.Repository) || r.ExpectedSourceRevision < 0 || len(r.MainGoMod) < 1 || len(r.MainGoMod) > gomodule.MaxGoMod ||
		r.LifetimeSeconds < 60 || r.LifetimeSeconds > 3600 || r.MaxArtifactBytes < 1 || r.MaxArtifactBytes > MaxGoExportSetArtifactBytes {
		return ErrGoRequirementExport
	}
	return nil
}

// Mod contains the actual consumed original .mod bytes. The source plan was
// obtained through current store admission before any external CAS read.
type GoRequirementRead struct {
	Plan GoExportPlan
	Mod  []byte
}

type GoRequirementMetadata struct {
	Name   string
	Object blob.Object
	Bytes  []byte
}

type GoRequirementExportPlan struct {
	tenant, actor    string
	request          GoRequirementExportRequest
	selection        GoExportSetPlan
	sources          []GoExportPlan
	manifest         GoRequirementExportManifest
	main, proof, raw []byte
}

func (p GoRequirementExportPlan) Bytes() []byte { return bytes.Clone(p.raw) }
func (p GoRequirementExportPlan) Object() blob.Object {
	return blob.Object{Digest: crypt.Digest(p.raw), Size: int64(len(p.raw))}
}
func (p GoRequirementExportPlan) Members() ([]GoExportPlan, error) { return p.selection.Members() }

// Callers must durably stage/sync every returned original before committing
// references. Bytes are private copies of the supplied project and metadata;
// treat them as private artifact data. Runtime credentials and signer material
// are never appended.
func (p GoRequirementExportPlan) Metadata() ([]GoRequirementMetadata, error) {
	if p.request.Validate() != nil || len(p.raw) < 1 || len(p.raw) > MaxGoRequirementExportManifest || len(p.sources) != len(p.manifest.Sources) {
		return nil, ErrGoRequirementExport
	}
	out := make([]GoRequirementMetadata, 0, len(p.sources)+4)
	add := func(name string, raw []byte) {
		out = append(out, GoRequirementMetadata{Name: name, Object: blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}, Bytes: bytes.Clone(raw)})
	}
	add("main.mod", p.main)
	add("requirements.json", p.proof)
	for n, source := range p.sources {
		add(fmt.Sprintf("input.%04d.manifest.json", n), source.raw)
	}
	add("selection.json", p.selection.raw)
	add("manifest.json", p.raw)
	return out, nil
}

// All original .mod reads occur before this method. It independently replays
// their bounded graph, then revalidates every input and selected root in the
// same final store snapshot. No persistent reference/session is created here.
func (s *Store) PlanGoRequirementExport(ctx context.Context, i Identity, r GoRequirementExportRequest, reads []GoRequirementRead) (GoRequirementExportPlan, error) {
	if r.Validate() != nil || len(reads) < 1 || len(reads) > gomodule.MaxRequirementProofSources {
		return GoRequirementExportPlan{}, ErrGoRequirementExport
	}
	if i.Role != "admin" {
		return GoRequirementExportPlan{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	inputs := make([]gomodule.RequirementInput, 0, len(reads))
	plans := make([]GoExportPlan, 0, len(reads))
	bySource := map[gomodule.Coordinate]GoExportPlan{}
	for _, read := range reads {
		if err := ctx.Err(); err != nil {
			return GoRequirementExportPlan{}, err
		}
		p := read.Plan
		c := p.Coordinate()
		if p.tenant != i.Tenant || p.actor != i.Actor || p.request.Repository != r.Repository || p.request.ExpectedSourceRevision != r.ExpectedSourceRevision ||
			p.request.Validate() != nil || len(p.manifest.Artifacts) != 3 || len(read.Mod) < 1 || len(read.Mod) > gomodule.MaxGoMod {
			return GoRequirementExportPlan{}, ErrGoRequirementExport
		}
		if _, exists := bySource[c]; exists {
			return GoRequirementExportPlan{}, ErrGoRequirementExport
		}
		object := p.Objects()[1]
		if int64(len(read.Mod)) != object.Size || crypt.Digest(read.Mod) != object.Digest {
			return GoRequirementExportPlan{}, ErrGoRequirementExport
		}
		inputs = append(inputs, gomodule.RequirementInput{Source: c, Mod: read.Mod})
		plans = append(plans, p)
		bySource[c] = p
	}
	main := []byte(r.MainGoMod)
	proof, graph, err := gomodule.BuildRequirementProof(ctx, main, inputs)
	if err != nil {
		return GoRequirementExportPlan{}, err
	}
	selectionRequest := GoExportSetRequest{LifetimeSeconds: r.LifetimeSeconds, MaxArtifactBytes: r.MaxArtifactBytes}
	for _, selected := range graph.BuildList {
		selectionRequest.Entries = append(selectionRequest.Entries, GoExportSetEntry{Repository: r.Repository, Module: selected.Source.Module, Version: selected.Source.Version, ExpectedSourceRevision: r.ExpectedSourceRevision})
	}
	selection, err := s.PlanGoExportSetAfterReads(ctx, i, selectionRequest, plans)
	if err != nil {
		return GoRequirementExportPlan{}, err
	}
	index, err := gomodule.ParseRequirementProof(proof)
	if err != nil {
		return GoRequirementExportPlan{}, err
	}
	p := GoRequirementExportPlan{tenant: i.Tenant, actor: i.Actor, request: r, selection: selection, main: bytes.Clone(main), proof: bytes.Clone(proof)}
	p.manifest = GoRequirementExportManifest{Profile: GoRequirementExportProfile, Selection: selection.manifest,
		MainGoMod: blob.Object{Digest: crypt.Digest(main), Size: int64(len(main))}, RequirementProof: blob.Object{Digest: crypt.Digest(proof), Size: int64(len(proof))}}
	for _, source := range index.Sources {
		old := bySource[gomodule.Coordinate{Module: source.Module, Version: source.Version}]
		m, err := ParseGoExportManifest(old.raw)
		if err != nil {
			return GoRequirementExportPlan{}, ErrGoRequirementExport
		}
		// All source metadata was compared with these exact originals in the
		// final snapshot. Only their observation fields change to that common
		// selection clock/head; no new file/DB read occurs outside the snapshot.
		m.PreparedAt = selection.manifest.PreparedAt
		m.ObservedJournal = selection.manifest.ObservedJournal
		raw, err := m.Bytes()
		if err != nil {
			return GoRequirementExportPlan{}, ErrGoRequirementExport
		}
		current := GoExportPlan{tenant: i.Tenant, actor: i.Actor, request: old.request, manifest: m, raw: raw}
		p.sources = append(p.sources, current)
		p.manifest.Sources = append(p.manifest.Sources, GoRequirementExportSource{Repository: m.Repository, SourceRevision: m.SourceRevision, Module: m.Module, Version: m.Version,
			Manifest: current.Object(), Mod: blob.Object{Digest: source.Mod.SHA256, Size: source.Mod.Size}})
	}
	p.raw, err = p.manifest.Bytes()
	if err != nil {
		return GoRequirementExportPlan{}, err
	}
	if _, err = BindGoRequirementProof(p.manifest, p.proof); err != nil {
		return GoRequirementExportPlan{}, err
	}
	return p, nil
}
