//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestComposerHostedLifecycleRestoresExactRetainedDistribution(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	ctx := context.Background()
	const repository = "cratectl-composer-lifecycle"
	const path = "dist/cratectl/composer-app/1.2.3.zip"
	const root = "/composer/" + repository + "/"
	const index = "p2/cratectl/composer-app.json"
	const endpoint = "/api/v1/repositories/" + repository + "/artifacts/lifecycle"
	mavenRepositories(t, s, admin, store.Repository{Name: repository, Format: "composer"})
	archive := composerFixture(t, "Owned inert Composer lifecycle fixture.")
	digest := crypt.Digest(archive)
	request := func(server *Server, method, target string, data []byte, status int) []byte {
		t.Helper()
		response := nugetHTTP(t, server, token, method, root+target, data, "")
		if response.Code != status {
			t.Fatalf("Composer %s %s returned %d, expected %d: %.250s", method, target, response.Code, status, response.Body.String())
		}
		return response.Body.Bytes()
	}
	request(s, "PUT", path, archive, 201)
	request(s, "GET", index, nil, 200)
	state, err := s.DB.ArtifactState(ctx, admin, repository, path)
	if err != nil {
		t.Fatal(err)
	}
	api := lifecycleHTTP(t, s, token)
	input := store.ArtifactStateRequest{Path: path, Digest: digest, Action: "delete", ExpectedRevision: state.Revision,
		Reason: "Retire the owned fixture package", DryRun: true}
	if w := api("PUT", endpoint, input, ""); w.Code != 200 {
		t.Fatal("preview Composer retirement", w.Code, w.Body.String())
	}
	request(s, "GET", path, nil, 200)
	input.DryRun = false
	w := api("PUT", endpoint, input, "cratectl-composer-delete")
	if w.Code != 200 {
		t.Fatal("delete Composer distribution", w.Code, w.Body.String())
	}
	replay := api("PUT", endpoint, input, "cratectl-composer-delete")
	if replay.Code != 200 || replay.Header().Get("Idempotent-Replayed") != "true" || !bytes.Equal(w.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("replaying Composer retirement changed its outcome")
	}
	request(s, "GET", index, nil, 404)
	request(s, "GET", path, nil, 404)
	request(s, "PUT", path, archive, 404)

	state, err = s.DB.ArtifactState(ctx, admin, repository, path)
	if err != nil || !state.Deleted {
		t.Fatal("Composer retirement state was not committed", state, err)
	}
	if check := api("GET", endpoint+"?path="+url.QueryEscape(path), nil, ""); check.Code != 200 {
		t.Fatal("inspect retained Composer state", check.Code)
	}
	input.Action, input.ExpectedRevision = "restore", state.Revision
	input.Reason = "Return the verified Composer distribution"
	file, err := s.Blobs.Open(admin.Tenant, digest)
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := name + ".cratectl-owned-unavailable"
	if err = os.Rename(name, unavailable); err != nil {
		t.Fatal(err)
	}
	w = api("PUT", endpoint, input, "cratectl-composer-restore")
	if err = os.Rename(unavailable, name); err != nil {
		t.Fatal(err)
	}
	if w.Code != 503 {
		t.Fatal("Composer restore did not require the retained archive bytes", w.Code, w.Body.String())
	}
	request(s, "GET", index, nil, 404)
	if w = api("PUT", endpoint, input, "cratectl-composer-restore"); w.Code != 200 {
		t.Fatal("restore the verified Composer distribution", w.Code, w.Body.String())
	}
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	request(restarted, "GET", index, nil, 200)
	if got := request(restarted, "GET", path, nil, 200); !bytes.Equal(got, archive) {
		t.Fatal("restored Composer distribution returned different bytes")
	}
}
