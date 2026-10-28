//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
	"time"
)

func TestForcedRLSAndPublication(t *testing.T) {
	dsn := os.Getenv("CRATECTL_DSN")
	if dsn == "" {
		t.Fatal("CRATECTL_DSN required: integration never silently skips")
	}
	ctx := context.Background()
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Pool.Close()
	var count int
	if e = s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.repositories`).Scan(&count); e != nil || count != 0 {
		t.Fatalf("unscoped query saw rows: %d %v", count, e)
	}
	a := Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	b := Identity{Tenant: "test-b", Actor: "operator", Role: "admin"}
	if e = s.Tx(ctx, a, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format) VALUES('test-b','escape','generic')`)
		return e
	}); e == nil {
		t.Fatal("RLS accepted other tenant insert")
	}
	for _, i := range []Identity{a, b} {
		if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format) VALUES($1,'same','generic') ON CONFLICT DO NOTHING`, i.Tenant)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if e = s.Publish(ctx, a, "same", []Artifact{{Path: "file", Digest: digest, Size: 1, MediaType: "text/plain"}}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, b, "same", "file"); e != ErrNotFound {
		t.Fatalf("tenant leak %v", e)
	}
	if e = s.Publish(ctx, a, "same", []Artifact{{Path: "file", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Size: 1, MediaType: "text/plain"}}); e == nil {
		t.Fatal("mutable blob coordinate")
	}
	events, e := s.Events(ctx, a, 0)
	if e != nil {
		t.Fatal(e)
	}
	last := events[len(events)-1]
	var body map[string]any
	if json.Unmarshal([]byte(last.Payload), &body) != nil || body["tenant"] != "test-a" {
		t.Fatal("wrong event")
	}
	if _, e = s.Pool.Exec(ctx, `UPDATE cratectl.events SET hash='forged'`); e == nil {
		t.Fatal("runtime could update journal")
	}
}

func TestOCIGraphPolicy(t *testing.T) {
	dsn := os.Getenv("CRATECTL_DSN")
	if dsn == "" {
		t.Fatal("CRATECTL_DSN required")
	}
	ctx := context.Background()
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Pool.Close()
	i := Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	image := fmt.Sprintf("graph-%d", time.Now().UnixNano())
	child := image + "/blobs/sha256:" + strings.Repeat("a", 64)
	parent := image + "/manifests/sha256:" + strings.Repeat("b", 64)
	metadata, _ := json.Marshal(OCIManifestMetadata{Validated: true, References: []string{child}, Descriptors: map[string]OCIDescriptor{child: {MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("a", 64), Size: 1}}})
	if e = s.Publish(ctx, i, "same", []Artifact{{Path: child, Digest: strings.Repeat("a", 64), Size: 1, MediaType: "application/octet-stream"}, {Path: parent, Digest: strings.Repeat("b", 64), Size: 1, MediaType: "application/vnd.oci.image.manifest.v1+json", Metadata: metadata}}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, "same", parent); e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='same' AND path=$1`, child)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, "same", parent); !errors.Is(e, ErrDenied) {
		t.Fatalf("served parent with denied child: %v", e)
	}
	if _, e = s.ArtifactForPublication(ctx, i, "same", parent); !errors.Is(e, ErrDenied) {
		t.Fatalf("intake accepted a known denied child: %v", e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='unassessed' WHERE repository='same' AND path=$1`, child)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// A malicious metadata cycle must terminate and fail closed rather than
	// recursing or treating a previously visited member as an approval.
	cycle, _ := json.Marshal(OCIManifestMetadata{Validated: true, References: []string{parent}, Descriptors: map[string]OCIDescriptor{parent: {MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:" + strings.Repeat("b", 64), Size: 1}}})
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=$1 WHERE repository='same' AND path=$2`, cycle, parent)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, "same", parent); !errors.Is(e, ErrDenied) {
		t.Fatalf("cycle did not fail closed: %v", e)
	}
}

func TestMetadataDecisionTracksExactBytes(t *testing.T) {
	dsn := os.Getenv("CRATECTL_DSN")
	if dsn == "" {
		t.Fatal("CRATECTL_DSN required")
	}
	ctx := context.Background()
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Pool.Close()
	i := Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	repo := fmt.Sprintf("metadata-%d", time.Now().UnixNano())
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,require_review) VALUES($1,$2,'maven',true)`, i.Tenant, repo)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	a := Artifact{Path: "maven-metadata.xml", Digest: strings.Repeat("a", 64), Size: 1, MediaType: "application/xml"}
	if e = s.ReplaceMetadata(ctx, i, repo, a); e != nil {
		t.Fatal(e)
	}
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository=$1`, repo)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.ReplaceMetadata(ctx, i, repo, a); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, repo, a.Path); e != nil {
		t.Fatalf("same bytes lost approval: %v", e)
	}
	a.Digest = strings.Repeat("b", 64)
	if e = s.ReplaceMetadata(ctx, i, repo, a); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Artifact(ctx, i, repo, a.Path); !errors.Is(e, ErrDenied) {
		t.Fatalf("changed bytes inherited approval: %v", e)
	}
}
