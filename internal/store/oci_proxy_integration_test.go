//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func ociCacheFixture(t *testing.T, fresh int) (*Store, context.Context, Identity, string, Retrieval, RetrievalResult) {
	t.Helper()
	s, ctx, i, base := npmTestStore(t)
	repo := base + "-cache"
	cfg := Repository{Name: repo, Format: "oci", Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "https://registry.example/v2/", Networks: []string{"0.0.0.0/0"}}}}
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, cfg) }); e != nil {
		t.Fatal(e)
	}
	child := Artifact{Path: "app/blobs/sha256:" + strings.Repeat("a", 64), Digest: strings.Repeat("a", 64), Size: 42, MediaType: "application/octet-stream"}
	metadata, _ := json.Marshal(OCIManifestMetadata{Validated: true, References: []string{child.Path}, Descriptors: map[string]OCIDescriptor{child.Path: {MediaType: "text/plain", Digest: "sha256:" + child.Digest, Size: child.Size}}})
	root := Artifact{Path: "app/manifests/sha256:" + strings.Repeat("b", 64), Digest: strings.Repeat("b", 64), Size: 123, MediaType: integrationOCIImage, Metadata: metadata}
	result := RetrievalResult{Status: 200, Object: &blob.Object{Digest: root.Digest, Size: root.Size}, Metadata: metadata, MediaType: root.MediaType, FreshSeconds: fresh, StaleSeconds: 120, OCI: &OCIPublication{Image: "app", Reference: "latest", Objects: []Artifact{root, child}, Tags: map[string]string{"latest": "sha256:" + root.Digest}}}
	lease, e := s.AcquireRetrieval(ctx, i, repo, "app/manifests/latest", "owned-initial", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, result); e != nil {
		t.Fatal(e)
	}
	return s, ctx, i, repo, lease, result
}

func invalidateOCI(t *testing.T, s *Store, ctx context.Context, i Identity, repo, path string) {
	t.Helper()
	if _, e := s.Mutate(ctx, i, "", "", "proxy.cache.invalidated", func(tx pgx.Tx) (any, int, error) {
		value, e := InvalidateRetrieval(ctx, tx, i, repo, path)
		return value, 200, e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestOCIZeroFreshnessAdmissionCannotSurviveInvalidation(t *testing.T) {
	s, ctx, i, repo, lease, result := ociCacheFixture(t, 0)
	if _, _, e := s.OCISelection(ctx, i, repo, "app", "manifests", "latest"); !errors.Is(e, ErrOCICacheExpired) {
		t.Fatalf("zero freshness became a cache hit: %v", e)
	}
	admission := OCIAdmission{Repository: repo, Path: lease.Path, Generation: lease.Generation}
	if _, _, e := s.OCISelection(ctx, i, repo, "app", "manifests", "latest", admission); e != nil {
		t.Fatalf("current positive validation not admitted: %v", e)
	}
	member := result.OCI.Objects[1].Path
	invalidateOCI(t, s, ctx, i, repo, member)
	if _, _, e := s.OCISelection(ctx, i, repo, "app", "manifests", "latest", admission); !errors.Is(e, ErrOCICacheExpired) {
		t.Fatalf("receipt bypassed member invalidation: %v", e)
	}
}

func TestOCIParentCannotOverwriteConcurrentMemberInvalidation(t *testing.T) {
	s, ctx, i, repo, _, result := ociCacheFixture(t, 60)
	lease, e := s.AcquireRetrieval(ctx, i, repo, "app/manifests/latest", "owned-parent", true)
	if e != nil {
		t.Fatal(e)
	}
	member := result.OCI.Objects[1].Path
	invalidateOCI(t, s, ctx, i, repo, member)
	// Simulate a backward wall-clock step without changing the host clock.
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET changed_at='epoch' WHERE repository=$1 AND path=$2`, repo, member)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, result); !errors.Is(e, ErrOCIMemberChanged) {
		t.Fatalf("parent erased a newer member invalidation: %v", e)
	}
	state, e := s.Retrieval(ctx, i, repo, member)
	if e != nil || state.LastError != "operator_revalidate" || state.Fresh() {
		t.Fatalf("member state lost: %+v %v", state, e)
	}
}

func TestOCIOlderTagFillCannotUndoNewerCatalogBinding(t *testing.T) {
	s, ctx, i, repo, _, old := ociCacheFixture(t, 60)
	lease, e := s.AcquireRetrieval(ctx, i, repo, "app/manifests/latest", "owned-old-tag", true)
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := s.AcquireRetrieval(ctx, i, repo, "oci-catalog/app/tags", "owned-new-catalog", true)
	if e != nil {
		t.Fatal(e)
	}
	root := old.OCI.Objects[0]
	root.Digest = strings.Repeat("c", 64)
	root.Path = "app/manifests/sha256:" + root.Digest
	tags := map[string]string{"latest": "sha256:" + root.Digest}
	metadata, _ := json.Marshal(OCICatalog{Image: "app", Tags: tags})
	result := RetrievalResult{Status: 200, Object: &blob.Object{Digest: crypt.Digest(metadata), Size: int64(len(metadata))}, Metadata: metadata, MediaType: OCICatalogMedia, FreshSeconds: 60, OCI: &OCIPublication{Image: "app", CompleteTags: true, Objects: []Artifact{root, old.OCI.Objects[1]}, Tags: tags}}
	if e = s.CompleteRetrieval(ctx, i, catalog, result); e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.tags SET changed_at='epoch' WHERE repository=$1`, repo)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 404, FreshSeconds: 60}); !errors.Is(e, ErrOCIMemberChanged) {
		t.Fatalf("older missing-tag result tombstoned a newer binding: %v", e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, old); !errors.Is(e, ErrOCIMemberChanged) {
		t.Fatalf("older tag fill rolled back newer catalog: %v", e)
	}
}

func TestOCIStaleGraphRequiresRequestReceiptAndEveryMemberWindow(t *testing.T) {
	s, ctx, i, repo, _, result := ociCacheFixture(t, 60)
	lease, e := s.AcquireRetrieval(ctx, i, repo, "app/manifests/latest", "owned-outage", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 503, Failure: "transient_upstream_failure"}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "latest"); !errors.Is(e, ErrOCICache) {
		t.Fatalf("stale graph admitted without outage receipt: %v", e)
	}
	admission := OCIAdmission{Repository: repo, Path: lease.Path, Generation: lease.Generation, Stale: true}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "latest", admission); e != nil {
		t.Fatalf("valid stale graph blocked: %v", e)
	}
	member := result.OCI.Objects[1].Path
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE repository=$1 AND path=$2`, repo, member)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "latest", admission); !errors.Is(e, ErrOCICacheExpired) {
		t.Fatalf("root window widened an expired member window: %v", e)
	}
	negative, e := s.AcquireRetrieval(ctx, i, repo, member, "owned-missing-member", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, negative, RetrievalResult{Status: 404, FreshSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "latest", admission); !errors.Is(e, ErrDenied) {
		t.Fatalf("outage receipt bypassed a member negative cache: %v", e)
	}
}

func TestOCIParentPreservesNewerFreshMemberValidation(t *testing.T) {
	s, ctx, i, repo, _, result := ociCacheFixture(t, 0)
	parent, e := s.AcquireRetrieval(ctx, i, repo, "app/manifests/latest", "owned-parent", true)
	if e != nil {
		t.Fatal(e)
	}
	member := result.OCI.Objects[1].Path
	child, e := s.AcquireRetrieval(ctx, i, repo, member, "owned-child", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, child, RetrievalResult{Status: 304, FreshSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	before, e := s.Retrieval(ctx, i, repo, member)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, parent, result); e != nil {
		t.Fatal(e)
	}
	after, e := s.Retrieval(ctx, i, repo, member)
	if e != nil || after.Generation != before.Generation || after.ChangeSequence != before.ChangeSequence {
		t.Fatalf("newer member validation overwritten: %+v %+v %v", before, after, e)
	}
	receipt := OCIAdmission{Repository: repo, Path: parent.Path, Generation: parent.Generation}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "latest", receipt); e != nil {
		t.Fatalf("mixed current validations blocked: %v", e)
	}
}

func TestOCIProxyGraphFenceAndAtomicPublication(t *testing.T) {
	s, ctx, i, base := npmTestStore(t)
	repo := base + "-proxy"
	cfg := Repository{Name: repo, Format: "oci", Mode: "proxy", RequireReview: true, Settings: RepositorySettings{Upstream: &upstream.Config{URL: "https://registry.example/v2/", Networks: []string{"0.0.0.0/0"}}}}
	if e := s.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, cfg) }); e != nil {
		t.Fatal(e)
	}
	child := Artifact{Path: "app/blobs/sha256:" + strings.Repeat("a", 64), Digest: strings.Repeat("a", 64), Size: 42, MediaType: "application/octet-stream"}
	metadata, _ := json.Marshal(OCIManifestMetadata{Validated: true, References: []string{child.Path}, Descriptors: map[string]OCIDescriptor{child.Path: {MediaType: "text/plain", Digest: "sha256:" + child.Digest, Size: child.Size}}})
	root := Artifact{Path: "app/manifests/sha256:" + strings.Repeat("b", 64), Digest: strings.Repeat("b", 64), Size: 123, MediaType: integrationOCIImage, Metadata: metadata}
	result := RetrievalResult{Status: 200, Object: &blob.Object{Digest: root.Digest, Size: root.Size}, Metadata: root.Metadata, MediaType: root.MediaType, FreshSeconds: 60, OCI: &OCIPublication{Image: "app", Reference: "latest", Objects: []Artifact{root, child}, Tags: map[string]string{"latest": "sha256:" + root.Digest}}}
	first, e := s.AcquireRetrieval(ctx, i, repo, "app/manifests/latest", "owned-first", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := InvalidateRetrieval(ctx, tx, i, repo, first.Path); return e }); e != nil {
		t.Fatal(e)
	}
	second, e := s.AcquireRetrieval(ctx, i, repo, first.Path, "owned-second", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, first, result); !errors.Is(e, ErrLeaseLost) {
		t.Fatalf("superseded graph published: %v", e)
	}
	if _, e = s.Artifact(ctx, i, repo, child.Path); !errors.Is(e, ErrNotFound) {
		t.Fatalf("fenced graph left child reference: %v", e)
	}
	partial := result
	publication := *result.OCI
	publication.Objects = []Artifact{root}
	partial.OCI = &publication
	if e = s.CompleteRetrieval(ctx, i, second, partial); !errors.Is(e, ErrNotFound) {
		t.Fatalf("missing child completed graph: %v", e)
	}
	if _, e = s.Artifact(ctx, i, repo, root.Path); !errors.Is(e, ErrNotFound) {
		t.Fatalf("partial graph left root reference: %v", e)
	}
	if e = s.CompleteRetrieval(ctx, i, second, result); e != nil {
		t.Fatal(e)
	}
	if _, e = s.OCIManifest(ctx, i, repo, "app", "latest"); !errors.Is(e, ErrDenied) {
		t.Fatalf("quarantine bypassed: %v", e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		for _, a := range []Artifact{child, root} {
			if _, e := Decide(ctx, tx, i, repo, a.Path, a.Digest, "allowed"); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	a, source, e := s.OCISelection(ctx, i, repo, "app", "manifests", "latest")
	if e != nil || a.Digest != root.Digest || source.Name != repo {
		t.Fatalf("current graph: %+v %+v %v", a, source, e)
	}
	canonicalPath := "app/manifests/sha256:" + root.Digest
	negative, e := s.AcquireRetrieval(ctx, i, repo, canonicalPath, "owned-negative", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteRetrieval(ctx, i, negative, RetrievalResult{Status: 404, FreshSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	refresh, e := s.AcquireRetrieval(ctx, i, repo, canonicalPath, "owned-refresh", true)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "sha256:"+root.Digest); !errors.Is(e, ErrBusy) {
		t.Fatalf("in-progress refresh bypassed previous negative cache: %v", e)
	}
	if e = s.CompleteRetrieval(ctx, i, refresh, RetrievalResult{Status: 304, FreshSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	other := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if _, _, e = s.OCISelection(ctx, other, repo, "app", "manifests", "latest"); !errors.Is(e, ErrNotFound) {
		t.Fatalf("cross-tenant graph: %v", e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error { _, e := Decide(ctx, tx, i, repo, child.Path, child.Digest, "denied"); return e }); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.OCISelection(ctx, i, repo, "app", "manifests", "latest"); !errors.Is(e, ErrDenied) {
		t.Fatalf("cached graph hid child denial: %v", e)
	}
}

func TestOCIGraphBudgetIsExplicitAndCheckedNodesRemainReusable(t *testing.T) {
	s, ctx, i, repo, _, result := ociCacheFixture(t, 60)
	member := result.OCI.Objects[1].Path
	if e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		budget := newGraphBudget()
		budget.remaining = 1
		if _, e := readArtifact(ctx, tx, repo, member, false, budget); e != nil {
			return e
		}
		if _, e := readArtifact(ctx, tx, repo, member, false, budget); e != nil {
			t.Fatalf("already checked node consumed another graph slot: %v", e)
		}
		if _, e := readArtifact(ctx, tx, repo, result.OCI.Objects[0].Path, false, budget); !errors.Is(e, ErrMetadataLimit) {
			t.Fatalf("graph ceiling looked like policy denial and could be filtered into partial discovery: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
