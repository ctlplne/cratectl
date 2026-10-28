//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

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
