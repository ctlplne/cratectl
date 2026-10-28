//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

const integrationOCIImage = "application/vnd.oci.image.manifest.v1+json"
const integrationOCIIndex = "application/vnd.oci.image.index.v1+json"

func ociStoreFixture(t *testing.T) (*Store, context.Context, Identity, string, Artifact, Artifact, OCIManifestMetadata) {
	t.Helper()
	s, ctx, i, base := npmTestStore(t)
	repo := base + "-oci"
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, Repository{Name: repo, Format: "oci"}) }); e != nil {
		t.Fatal(e)
	}
	child := Artifact{Path: "app/blobs/sha256:" + strings.Repeat("1", 64), Digest: strings.Repeat("1", 64), Size: 42, MediaType: "application/octet-stream"}
	root := Artifact{Path: "app/manifests/sha256:" + strings.Repeat("2", 64), Digest: strings.Repeat("2", 64), Size: 123, MediaType: integrationOCIImage}
	metadata := OCIManifestMetadata{Validated: true, References: []string{child.Path}, Descriptors: map[string]OCIDescriptor{child.Path: {"text/plain", "sha256:" + child.Digest, child.Size}}, ArtifactType: "application/vnd.cratectl.proof"}
	if e := s.Publish(ctx, i, repo, []Artifact{child}); e != nil {
		t.Fatal(e)
	}
	return s, ctx, i, repo, child, root, metadata
}
func publishOCIFixture(s *Store, ctx context.Context, i Identity, repo string, a Artifact, m OCIManifestMetadata) error {
	_, e := s.MutateRepository(ctx, i, repo, "", "", "oci.manifest.published", func(tx pgx.Tx) (any, int, error) {
		return map[string]string{"path": a.Path}, 201, PublishOCI(ctx, tx, i, repo, "app", "latest", a, m)
	})
	return e
}
func TestOCIIntakeRechecksDescriptorAndPolicyAtomically(t *testing.T) {
	s, ctx, i, repo, child, root, metadata := ociStoreFixture(t)
	bad := metadata
	bad.Descriptors = map[string]OCIDescriptor{child.Path: {"text/plain", "sha256:" + child.Digest, 43}}
	if e := publishOCIFixture(s, ctx, i, repo, root, bad); !errors.Is(e, ErrConflict) {
		t.Fatalf("wrong child size: %v", e)
	}
	if _, e := s.Artifact(ctx, i, repo, root.Path); !errors.Is(e, ErrNotFound) {
		t.Fatalf("failed intake left root: %v", e)
	}
	if tags, e := s.Tags(ctx, i, repo, "app"); e != nil || len(tags) != 0 {
		t.Fatalf("failed intake left tag: %v %v", tags, e)
	}
	if _, e := s.ArtifactForPublication(ctx, i, repo, child.Path); e != nil {
		t.Fatal(e)
	}
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := Decide(ctx, tx, i, repo, child.Path, child.Digest, "denied"); return e }); e != nil {
		t.Fatal(e)
	}
	if e := publishOCIFixture(s, ctx, i, repo, root, metadata); !errors.Is(e, ErrDenied) {
		t.Fatalf("preflight hid a current child denial: %v", e)
	}
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := Decide(ctx, tx, i, repo, child.Path, child.Digest, "allowed"); return e }); e != nil {
		t.Fatal(e)
	}
	if e := publishOCIFixture(s, ctx, i, repo, root, metadata); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Artifact(ctx, i, repo, root.Path); e != nil {
		t.Fatal(e)
	}
	changed := root
	changed.MediaType = "application/vnd.docker.distribution.manifest.v2+json"
	if e := publishOCIFixture(s, ctx, i, repo, changed, metadata); !errors.Is(e, ErrConflict) {
		t.Fatalf("immutable root media changed: %v", e)
	}
	// A same-byte writer replay enriches legacy metadata, preserving decisions.
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata='{"oci_references":[]}' WHERE repository=$1 AND path=$2`, repo, root.Path)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Artifact(ctx, i, repo, root.Path); !errors.Is(e, ErrOCIUnvalidated) {
		t.Fatalf("legacy manifest was served without structure validation: %v", e)
	}
	if e := publishOCIFixture(s, ctx, i, repo, root, metadata); e != nil {
		t.Fatal(e)
	}
	a, e := s.Artifact(ctx, i, repo, root.Path)
	var stored OCIManifestMetadata
	if e != nil || json.Unmarshal(a.Metadata, &stored) != nil || !stored.Validated || len(stored.References) != 1 {
		t.Fatalf("same-byte enrichment: %+v %v", a, e)
	}
}

func TestOCIWeakSubjectReferrersCurrentPolicyAndBounds(t *testing.T) {
	s, ctx, i, repo, _, attachment, metadata := ociStoreFixture(t)
	subject := Artifact{Path: "app/manifests/sha256:" + strings.Repeat("3", 64), Digest: strings.Repeat("3", 64), Size: 87, MediaType: integrationOCIIndex}
	metadata.Subject = &OCIDescriptor{subject.MediaType, "sha256:" + subject.Digest, subject.Size}
	metadata.Annotations = map[string]string{"org.opencontainers.image.description": "owned attachment"}
	if e := publishOCIFixture(s, ctx, i, repo, attachment, metadata); e != nil {
		t.Fatalf("out-of-order subject: %v", e)
	}
	refs, e := s.OCIReferrers(ctx, i, repo, "app", metadata.Subject.Digest, "", 10, 1<<20)
	if e != nil || len(refs) != 1 || refs[0].Digest != "sha256:"+attachment.Digest || refs[0].ArtifactType != metadata.ArtifactType {
		t.Fatalf("weak subject discovery: %+v %v", refs, e)
	}
	if refs, e = s.OCIReferrers(ctx, i, repo, "app", metadata.Subject.Digest, "application/vnd.other", 10, 1<<20); e != nil || len(refs) != 0 {
		t.Fatalf("type filter: %v %v", refs, e)
	}
	if _, e = s.OCIReferrers(ctx, i, repo, "app", metadata.Subject.Digest, "", 10, 1); !errors.Is(e, ErrMetadataLimit) {
		t.Fatalf("metadata budget: %v", e)
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, e = s.OCIReferrers(ctx, other, repo, "app", metadata.Subject.Digest, "", 10, 1<<20); !errors.Is(e, ErrNotFound) {
		t.Fatalf("cross-tenant discovery: %v", e)
	}
	subjectMetadata := OCIManifestMetadata{Validated: true, References: []string{}, Descriptors: map[string]OCIDescriptor{}}
	if e = publishOCIFixture(s, ctx, i, repo, subject, subjectMetadata); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, repo, attachment.Path); e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := Decide(ctx, tx, i, repo, subject.Path, subject.Digest, "denied")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, repo, attachment.Path); !errors.Is(e, ErrDenied) {
		t.Fatalf("late subject denial did not block attachment: %v", e)
	}
	if _, e = s.OCIReferrers(ctx, i, repo, "app", metadata.Subject.Digest, "", 10, 1<<20); !errors.Is(e, ErrDenied) {
		t.Fatalf("denied subject index: %v", e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := Decide(ctx, tx, i, repo, subject.Path, subject.Digest, "allowed")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := Decide(ctx, tx, i, repo, attachment.Path, attachment.Digest, "denied")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if refs, e = s.OCIReferrers(ctx, i, repo, "app", metadata.Subject.Digest, "", 10, 1<<20); e != nil || len(refs) != 0 {
		t.Fatalf("denied referrer leaked: %v %v", refs, e)
	}
}
