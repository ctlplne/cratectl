//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestCRANOrderedGroupBindsOwningSourceAndCurrentPolicy(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	const first, lower, group, explicit = "cratectl-cran-first", "cratectl-cran-lower", "cratectl-cran-group", "cratectl-cran-owner"
	const name, version = "CratectlStats", "1.10.0"
	const directory = "src/contrib/"
	const app = directory + "CratectlStats_1.10.0.tar.gz"
	const dep = directory + "Cratectl.Data_2.2-0.tar.gz"
	const lowerOnly = directory + "CratectlStats_2.0.0.tar.gz"
	const index = directory + "PACKAGES"
	for _, repo := range []string{first, lower} {
		mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "cran", Access: "restricted", RequireReview: repo == first})
	}
	members := []string{first, lower}
	mavenRepositories(t, s, admin,
		store.Repository{Name: group, Format: "cran", Mode: "group", Access: "restricted", RequireReview: true, Settings: store.RepositorySettings{Members: members}},
		store.Repository{Name: explicit, Format: "cran", Mode: "group", Access: "restricted", RequireReview: true,
			Settings: store.RepositorySettings{Members: members, NamespaceOwners: map[string]string{name + "/": lower}}})

	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	const actor = "cratectl-cran-group-reader"
	if err := store.Provision(ctx, database.OwnerDSN, admin.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := s.DB.Authenticate(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	api := lifecycleHTTP(t, s, token)
	grant := func(repo string, enabled bool) {
		t.Helper()
		key := "cratectl-cran-group-grant-" + repo
		if !enabled {
			key += "-revoke"
		}
		if w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": enabled}, key); w.Code != 200 {
			t.Fatalf("change CRAN group grant: %d %.250s", w.Code, w.Body.String())
		}
	}
	request := func(repo, credential, method, path string, body []byte, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, s, credential, method, "/cran/"+repo+"/"+path, body, "")
		if w.Code != want {
			t.Fatalf("CRAN %s %s %s returned %d, want %d: %.250s", repo, method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	decide := func(repo, path, digest, decision string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, path, digest, decision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	const description = "Description: Owned grouped package.\nImports: Cratectl.Data (>= 2.2-0)\n"
	preferredBytes := cranSourceFixture(t, name, version, description, "Owned preferred archive.\n")
	lowerBytes := cranSourceFixture(t, name, version, description, "Owned colliding lower archive.\n")
	lowerVersion := cranSourceFixture(t, name, "2.0.0", description, "Owned lower-only version.\n")
	dependency := cranSourceFixture(t, "Cratectl.Data", "2.2-0", "Description: Owned group dependency.\n", "Owned dependency archive.\n")
	pin := func(path, digest string) string {
		return directory + "sha256/" + digest + "/" + strings.TrimPrefix(path, directory)
	}
	lowerDigest, preferredDigest, depDigest := crypt.Digest(lowerBytes), crypt.Digest(preferredBytes), crypt.Digest(dependency)
	lowerPin, preferredPin := pin(app, lowerDigest), pin(app, preferredDigest)
	depPin := pin(dep, depDigest)
	for _, repo := range []string{group, explicit, lower} {
		grant(repo, true)
	}
	request(lower, token, "PUT", app, lowerBytes, 201)
	request(lower, token, "PUT", lowerOnly, lowerVersion, 201)
	request(lower, token, "PUT", dep, dependency, 201)
	decide(lower, app, lowerDigest, "allowed")
	decide(lower, lowerOnly, crypt.Digest(lowerVersion), "allowed")
	request(group, reader, "GET", index, nil, 403)
	request(group, reader, "GET", lowerPin, nil, 403)
	grant(first, true)
	w := request(group, reader, "GET", index, nil, 200)
	if !strings.Contains(w.Body.String(), "Path: sha256/"+lowerDigest+"\n") || strings.Contains(w.Body.String(), "Package: Cratectl.Data\n") {
		t.Fatal("group index missed the lower owner or allowed an unreviewed dependency")
	}
	request(group, reader, "GET", depPin, nil, 403)
	decide(lower, dep, depDigest, "allowed")
	if got := request(group, reader, "GET", lowerPin, nil, 200); !bytes.Equal(got.Body.Bytes(), lowerBytes) || got.Header().Get("X-Cratectl-Repository") != lower {
		t.Fatal("ordered absence did not admit the exact lower source")
	}
	endpoint, err := s.DB.Repository(ctx, identity, group)
	if err != nil {
		t.Fatal(err)
	}
	selected, source, err := s.DB.CRANGroupArtifact(ctx, identity, group, app, lowerDigest, endpoint.SourceRevision)
	if err != nil {
		t.Fatal(err)
	}
	prior := resolvedArtifact{artifact: selected, source: source, groups: []string{group}, groupRevisions: map[string]int64{group: endpoint.SourceRevision}}
	request(first, token, "PUT", app, preferredBytes, 201)
	request(group, token, "PUT", app, lowerBytes, 405)
	request(group, reader, "GET", app, nil, 404)
	request(group, reader, "GET", lowerPin, nil, 403)
	if _, err := s.guardResolved(ctx, identity, prior); !errors.Is(err, store.ErrDenied) {
		t.Fatalf("an admitted lower reference bypassed the new current owner: %v", err)
	}
	decide(first, app, preferredDigest, "allowed")
	w = request(group, reader, "GET", index, nil, 200)
	if !strings.Contains(w.Body.String(), "Path: sha256/"+preferredDigest+"\n") || !strings.Contains(w.Body.String(), "Path: sha256/"+depDigest+"\n") ||
		strings.Contains(w.Body.String(), "Version: 2.0.0") || strings.Contains(w.Body.String(), lowerDigest) {
		t.Fatal("the grouped source index did not preserve first ownership and independent dependency sources")
	}
	request(group, reader, "GET", lowerPin, nil, 409)
	request(group, reader, "GET", pin(lowerOnly, crypt.Digest(lowerVersion)), nil, 404)
	if got := request(group, reader, "GET", preferredPin, nil, 200); !bytes.Equal(got.Body.Bytes(), preferredBytes) || got.Header().Get("X-Cratectl-Repository") != first {
		t.Fatal("CRAN group did not read the exact preferred archive")
	}
	if got := request(explicit, reader, "GET", lowerPin, nil, 200); !bytes.Equal(got.Body.Bytes(), lowerBytes) {
		t.Fatal("explicit CRAN ownership did not select the lower source")
	}
	state, err := s.DB.ArtifactState(ctx, admin, first, app)
	if err != nil {
		t.Fatal(err)
	}
	input := store.ArtifactStateRequest{Path: app, Digest: preferredDigest, Action: "delete", ExpectedRevision: state.Revision,
		Reason: "Retire the owned preferred CRAN archive"}
	if result := api("PUT", "/api/v1/repositories/"+first+"/artifacts/lifecycle", input, "cratectl-cran-group-delete"); result.Code != 200 {
		t.Fatalf("retire preferred CRAN ownership: %d %.250s", result.Code, result.Body.String())
	}
	if w := request(group, reader, "GET", index, nil, 200); strings.Contains(w.Body.String(), "Package: "+name+"\n") {
		t.Fatal("retired preferred source released the package name to the lower member")
	}
	request(group, reader, "GET", lowerPin, nil, 404)
	grant(lower, false)
	request(group, reader, "GET", index, nil, 403)
	request(group, reader, "GET", depPin, nil, 403)
}
