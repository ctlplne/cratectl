//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/cargo"
	"ctlplne.dev/cratectl/internal/store"
)

func TestCargoGroupServingRechecksFirstMemberBeforeHeaders(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		review bool
		err    error
		status int
	}{
		{"new-servable-source", false, store.ErrConflict, http.StatusConflict},
		{"new-unassessed-source", true, store.ErrDenied, http.StatusForbidden},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, _, _, i := schemaServer(t)
			ctx := t.Context()
			mavenRepositories(t, s, i,
				store.Repository{Name: "first", Format: "cargo", Access: "restricted", RequireReview: scenario.review},
				store.Repository{Name: "lower", Format: "cargo", Access: "restricted"},
				store.Repository{Name: "combined", Format: "cargo", Access: "restricted", Mode: "group",
					Settings: store.RepositorySettings{Members: []string{"first", "lower"}}})
			const name, version = "cratectl-cargo-selection", "1.0.0"
			path, err := cargo.ArtifactPath(name, version)
			if err != nil {
				t.Fatal(err)
			}
			publish := func(repo, payload string) {
				t.Helper()
				body, err := s.Blobs.Put(ctx, i.Tenant, strings.NewReader(payload), "", int64(len(payload)))
				if err != nil {
					t.Fatal(err)
				}
				err = s.DB.PublishCargo(ctx, i, repo, store.Artifact{Path: path, Digest: body.Digest,
					Size: body.Size, MediaType: cargo.MediaType}, cargo.Entry{
					Name: name, Version: version, Features: map[string][]string{}, Dependencies: []cargo.Dependency{},
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			publish("lower", "original lower candidate bytes")
			artifact, source, err := s.DB.CargoDownload(ctx, i, "combined", name, version)
			if err != nil || source.Name != "lower" {
				t.Fatalf("initial source %q: %v", source.Name, err)
			}
			resolved := resolvedArtifact{artifact: artifact, source: source, cargo: &cargoRead{"combined", name, version}}
			file, err := s.Blobs.OpenVerified(ctx, i.Tenant, artifact.Digest, artifact.Size)
			if err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			publish("first", "new preferred candidate bytes")
			if _, err = s.guardResolved(ctx, i, resolved); !errors.Is(err, scenario.err) {
				t.Fatalf("selection guard returned %v, want %v", err, scenario.err)
			}
			reply := httptest.NewRecorder()
			s.serveResolvedArtifact(reply, httptest.NewRequest(http.MethodGet, "/cargo/combined/download/"+name+"/"+version, nil), i, resolved)
			if reply.Code != scenario.status || reply.Header().Get("X-Checksum-Sha256") != "" ||
				reply.Header().Get("ETag") != "" || strings.Contains(reply.Body.String(), "original lower candidate bytes") {
				t.Fatalf("stale selection committed headers or bytes: status=%d headers=%v", reply.Code, reply.Header())
			}
		})
	}
}
