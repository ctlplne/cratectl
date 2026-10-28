//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func npmTestStore(t *testing.T) (*Store, context.Context, Identity, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if os.Getenv("CRATECTL_DSN") == "" {
		t.Fatal("CRATECTL_DSN required: integration never silently skips")
	}
	s, e := Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Pool.Close)
	i := Identity{Tenant: "test-a", Actor: "operator", Role: "admin"}
	repo := fmt.Sprintf("npm-%d", time.Now().UnixNano())
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, i, Repository{Name: repo, Format: "npm"})
	}); e != nil {
		t.Fatal(e)
	}
	return s, ctx, i, repo
}

func npmTestArtifact(version, digest string) Artifact {
	metadata, _ := json.Marshal(map[string]any{"name": "@test/package", "version": version, "package": map[string]any{"name": "@test/package", "version": version, "dist": map[string]any{}}})
	return Artifact{Path: NPMPath("@test/package", version), Digest: strings.Repeat(digest, 64), Size: 1, MediaType: "application/octet-stream", Metadata: metadata}
}

func TestDigestDecisionsCoverExistingAndFutureAliases(t *testing.T) {
	s, ctx, i, repo := npmTestStore(t)
	first := npmTestArtifact("1.0.0", "d")
	second := npmTestArtifact("2.0.0", "d")
	if e := s.PublishNPM(ctx, i, repo, "@test/package", []Artifact{first}, map[string]string{"latest": "1.0.0"}); e != nil {
		t.Fatal(e)
	}
	if e := s.PublishNPM(ctx, i, repo, "@test/package", []Artifact{second}, map[string]string{"latest": "2.0.0"}); e != nil {
		t.Fatal(e)
	}
	decide := func(decision string) Result {
		t.Helper()
		result, e := s.MutateRepository(ctx, i, repo, repo+"-"+decision, repo+"-"+decision, "artifact.decided", func(tx pgx.Tx) (any, int, error) {
			v, e := Decide(ctx, tx, i, repo, first.Path, first.Digest, decision)
			return v, 200, e
		})
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	decision := decide("denied")
	if replay := decide("denied"); !replay.Replay || string(replay.Body) != string(decision.Body) {
		t.Fatal("digest decision replay changed the result")
	}
	third := npmTestArtifact("3.0.0", "d")
	if e := s.PublishNPM(ctx, i, repo, "@test/package", []Artifact{third}, map[string]string{"latest": "3.0.0"}); e != nil {
		t.Fatal(e)
	}
	for _, a := range []Artifact{first, second, third} {
		if _, e := s.Artifact(ctx, i, repo, a.Path); !errors.Is(e, ErrDenied) {
			t.Fatalf("denied digest alias %s was visible: %v", a.Path, e)
		}
	}
	artifacts, tags, e := s.NPMState(ctx, i, repo, "@test/package", 10, 1<<20)
	if e != nil || len(artifacts) != 0 || len(tags) != 0 {
		t.Fatalf("denied npm versions/tags leaked: %d %v %v", len(artifacts), tags, e)
	}
	if e = s.ChangeNPMTag(ctx, i, repo, "@test/package", "stable", "1.0.0", false); !errors.Is(e, ErrDenied) {
		t.Fatalf("tag creation accepted denied target: %v", e)
	}
	for _, identity := range []Identity{i, {Tenant: "test-b", Actor: "operator", Role: "admin"}} {
		otherRepo := repo
		if identity.Tenant == i.Tenant {
			otherRepo += "-other"
		}
		if e = s.Tx(ctx, identity, true, func(tx pgx.Tx) error {
			return CreateRepository(ctx, tx, identity, Repository{Name: otherRepo, Format: "npm"})
		}); e != nil {
			t.Fatal(e)
		}
		if e = s.Publish(ctx, identity, otherRepo, []Artifact{first}); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Artifact(ctx, identity, otherRepo, first.Path); e != nil {
			t.Fatalf("decision crossed tenant/repository authority: %v", e)
		}
	}
	decide("allowed")
	if _, e = s.Artifact(ctx, i, repo, third.Path); e != nil {
		t.Fatalf("later approval did not cover future alias: %v", e)
	}
	for _, table := range []string{"content_decisions", "npm_tags"} {
		var n int
		if e = s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.`+table).Scan(&n); e != nil || n != 0 {
			t.Fatalf("unscoped %s query exposed rows: %d %v", table, n, e)
		}
	}
}

func TestNPMTagsBudgetsAndPublicationRollback(t *testing.T) {
	s, ctx, i, repo := npmTestStore(t)
	name := "@test/package"
	first, second := npmTestArtifact("1.0.0", "a"), npmTestArtifact("2.0.0", "b")
	if e := s.PublishNPM(ctx, i, repo, name, []Artifact{first}, map[string]string{"latest": "1.0.0"}, 1); e != nil {
		t.Fatal(e)
	}
	if e := s.PublishNPM(ctx, i, repo, name, []Artifact{second}, map[string]string{"stable": "2.0.0"}, 1); !errors.Is(e, ErrMetadataLimit) {
		t.Fatalf("tag budget not enforced: %v", e)
	}
	if _, e := s.Artifact(ctx, i, repo, second.Path); !errors.Is(e, ErrNotFound) {
		t.Fatal("failed tag change partially published a version", e)
	}
	if e := s.PublishNPM(ctx, i, repo, name, []Artifact{second}, map[string]string{"latest": "2.0.0"}, 1); e != nil {
		t.Fatal(e)
	}
	as, tags, e := s.NPMState(ctx, i, repo, name, 2, 1<<20, 1)
	if e != nil || len(as) != 2 || tags["latest"] != "2.0.0" {
		t.Fatalf("metadata query lost versions or current tag: %d %v %v", len(as), tags, e)
	}
	for _, budget := range []struct {
		versions int
		bytes    int64
	}{{1, 1 << 20}, {2, 1}} {
		if _, _, e = s.NPMState(ctx, i, repo, name, budget.versions, budget.bytes); !errors.Is(e, ErrMetadataLimit) {
			t.Fatalf("index silently truncated instead of rejecting its budget: %v", e)
		}
	}
	reader := Identity{Tenant: i.Tenant, Actor: "reader", Role: "reader"}
	if e = s.ChangeNPMTag(ctx, reader, repo, name, "latest", "", true); !errors.Is(e, ErrDenied) {
		t.Fatal("reader removed tag", e)
	}
	if e = s.ChangeNPMTag(ctx, i, repo, name, "latest", "", true); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("CRATECTL_OWNER_DSN") == "" {
		t.Fatal("CRATECTL_OWNER_DSN required to verify migration replay")
	}
	if e = Migrate(ctx, os.Getenv("CRATECTL_OWNER_DSN")); e != nil {
		t.Fatal(e)
	}
	_, tags, e = s.NPMState(ctx, i, repo, name, 2, 1<<20, 1)
	if e != nil || len(tags) != 0 {
		t.Fatal("deleted tag remained visible", tags, e)
	}
	if e = s.ChangeNPMTag(ctx, i, repo, name, "stable", "1.0.0", false, 1); e != nil {
		t.Fatalf("deleted tag consumed active-tag budget: %v", e)
	}
}

func TestNPMIndexSnapshotDuringPublication(t *testing.T) {
	s, ctx, i, repo := npmTestStore(t)
	name := "@test/package"
	if e := s.PublishNPM(ctx, i, repo, name, []Artifact{npmTestArtifact("1.0.0", "a")}, map[string]string{"latest": "1.0.0"}); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		for n := 2; n <= 30; n++ {
			version := fmt.Sprintf("%d.0.0", n)
			if e := s.PublishNPM(ctx, i, repo, name, []Artifact{npmTestArtifact(version, "a")}, map[string]string{"latest": version}); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	var readError error
	for n := 0; n < 50; n++ {
		artifacts, tags, e := s.NPMState(ctx, i, repo, name, 100, 1<<20)
		if e != nil {
			readError = e
			break
		}
		visible := map[string]bool{}
		for _, a := range artifacts {
			var m struct {
				Version string `json:"version"`
			}
			if e = json.Unmarshal(a.Metadata, &m); e != nil {
				readError = e
				break
			}
			visible[m.Version] = true
		}
		if !visible[tags["latest"]] {
			readError = fmt.Errorf("tag and version list came from incompatible publication states: %v", tags)
			break
		}
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if readError != nil {
		t.Fatal(readError)
	}
}
