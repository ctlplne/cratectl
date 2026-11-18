//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/cargo"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
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
			resolved := resolvedArtifact{artifact: artifact, source: source,
				cargo: &cargoRead{repository: "combined", name: name, version: version}}
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

func TestCargoGroupRechecksProxyAbsenceBeforeLowerDelivery(t *testing.T) {
	s, _, _, i := schemaServer(t)
	ctx := t.Context()
	mavenRepositories(t, s, i,
		store.Repository{Name: "preferred", Format: "cargo", Mode: "proxy", Settings: store.RepositorySettings{
			Upstream: &upstream.Config{URL: "https://registry.example/", Networks: []string{"192.0.2.0/24"}},
		}},
		store.Repository{Name: "lower", Format: "cargo"},
		store.Repository{Name: "combined", Format: "cargo", Mode: "group", Settings: store.RepositorySettings{
			Members: []string{"preferred", "lower"},
		}})
	const name, version = "cratectl-cargo-proxy-selection", "1.0.0"
	p, err := cargo.ArtifactPath(name, version)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("verified immutable bytes in the lower fixture")
	object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(body), "", int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	entry := cargo.Entry{Name: name, Version: version, Features: map[string][]string{}, Dependencies: []cargo.Dependency{}}
	if err = s.DB.PublishCargo(ctx, i, "lower", store.Artifact{Path: p, Digest: object.Digest, Size: object.Size, MediaType: cargo.MediaType}, entry); err != nil {
		t.Fatal(err)
	}
	catalogPath := store.CargoCatalogPath(name)
	negative, err := s.DB.AcquireRetrieval(ctx, i, "preferred", catalogPath, "initial-absence", true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DB.CompleteRetrieval(ctx, i, negative, store.RetrievalResult{Status: 404, FreshSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	route, err := s.DB.CargoGroupMember(ctx, i, "combined", name, 0, nil, nil)
	if err != nil || route.Member.Name != "lower" {
		t.Fatalf("ordered absence selected %q: %v", route.Member.Name, err)
	}
	artifact, source, err := s.DB.CargoDownload(ctx, i, "combined", name, version, &route)
	if err != nil {
		t.Fatal(err)
	}
	positive, err := s.DB.AcquireRetrieval(ctx, i, "preferred", catalogPath, "latest-catalog", true)
	if err != nil {
		t.Fatal(err)
	}
	entry.Checksum = crypt.Digest([]byte("different preferred archive identity"))
	row := cargo.SparseEntry{Entry: entry}
	metadata, err := store.CargoCanonicalSource(row)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(store.CargoCatalog{Name: name, Entries: []cargo.SparseEntry{row}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), "", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	key := store.CargoSourceKey(name, version)
	publication := &store.NativeCatalogPublication{Name: name, Entries: map[string]string{version: key}, Sources: []store.NativeSource{{
		Key: key, Format: "cargo", Name: name, Coordinate: version, Version: version, URL: "https://registry.example/file.crate",
		Integrity: "sha256:" + entry.Checksum, Metadata: metadata,
	}}}
	if err = s.DB.CompleteRetrieval(ctx, i, positive, store.RetrievalResult{Status: 200, FreshSeconds: 60,
		Object: &catalog, MediaType: store.CargoCatalogMedia, Metadata: data, NativeCatalog: publication}); err != nil {
		t.Fatal(err)
	}
	reply := httptest.NewRecorder()
	s.serveResolvedArtifact(reply, httptest.NewRequest(http.MethodGet, "/cargo/combined/download/"+name+"/"+version, nil), i,
		resolvedArtifact{artifact: artifact, source: source, cargo: &cargoRead{repository: "combined", name: name, version: version, group: &route}})
	if reply.Code != http.StatusConflict || reply.Header().Get("X-Checksum-Sha256") != "" || bytes.Contains(reply.Body.Bytes(), body) {
		t.Fatalf("expired lower selection committed a header or byte: %d %v", reply.Code, reply.Header())
	}
}
