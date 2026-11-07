//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"io"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func TestGoModuleRequirementExportPlanStagesEveryOriginalMetadataReferenceWithoutSession(t *testing.T) {
	f, one := hostedExportFixture(t)
	ctx := context.Background()
	source, err := f.s.PlanGoExport(ctx, f.i, one)
	if err != nil {
		t.Fatal(err)
	}
	object := source.Objects()[1]
	file, err := f.objects.OpenVerified(ctx, f.i.Tenant, object.Digest, object.Size)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := io.ReadAll(io.LimitReader(file, gomodule.MaxGoMod+1))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	request := GoRequirementExportRequest{Repository: one.Repository, ExpectedSourceRevision: one.ExpectedSourceRevision,
		MainGoMod: "module owned/main\ngo 1.27.0\nrequire " + one.Module + " " + one.Version + "\n", LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20}
	before := exportSetCounts(t, f)
	p, err := f.s.PlanGoRequirementExport(ctx, f.i, request, []GoRequirementRead{{Plan: source, Mod: mod}})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := ParseGoRequirementExportManifest(p.Bytes())
	if err != nil || len(parent.Sources) != 1 || len(parent.Selection.Entries) != 1 || parent.Selection.DependencyClosure {
		t.Fatal("invalid current graph parent", err)
	}
	metadata, err := p.Metadata()
	if err != nil || len(metadata) != 5 {
		t.Fatal("incomplete original graph metadata staging inventory", len(metadata), err)
	}
	original := bytes.Clone(metadata[0].Bytes)
	metadata[0].Bytes[0] ^= 1
	again, err := p.Metadata()
	if err != nil || !bytes.Equal(again[0].Bytes, original) {
		t.Fatal("caller modified the immutable plan", err)
	}
	for _, item := range again {
		if item.Object.Digest != crypt.Digest(item.Bytes) || item.Object.Size != int64(len(item.Bytes)) {
			t.Fatal("staged reference does not identify its original bytes")
		}
		if staged, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(item.Bytes), item.Object.Digest, item.Object.Size); err != nil || staged != item.Object {
			t.Fatal("original metadata staging", item.Name, err)
		}
	}
	input, err := BindGoRequirementSourceManifest(parent, 0, again[2].Bytes)
	if err != nil || !input.PreparedAt.Equal(parent.Selection.PreparedAt) || input.ObservedJournal != parent.Selection.ObservedJournal {
		t.Fatal("examined source did not retain the common observation", err)
	}
	if _, err := BindGoRequirementProof(parent, again[1].Bytes); err != nil {
		t.Fatal("graph index differs from original parent references", err)
	}
	if members, err := p.Members(); err != nil || len(members) != 1 {
		t.Fatal("selected physical inspection plans missing", err)
	}
	if after := exportSetCounts(t, f); after != before {
		t.Fatal("read-only planning/staging created a partial session or event", before, after)
	}
}
