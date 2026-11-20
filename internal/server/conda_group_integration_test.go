//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestCondaGroupBindsCurrentPlatformSnapshotAndOwnership(t *testing.T) {
	s, database, token, owner := schemaServer(t)
	s.PublicURL = "https://127.0.0.1:38443"
	ctx := context.Background()
	const first = "cratectl-conda-first"
	const lower = "cratectl-conda-lower"
	const group = "cratectl-conda-group"
	const override = "cratectl-conda-override"
	const actor = "cratectl-conda-group-reader"
	const appName = "cratectl-conda-dependency"
	const appFile = appName + "-1.0.0-hfixture_0.tar.bz2"
	const portableFile = "cratectl-conda-archive-1.2.0-hfixture_1.tar.bz2"
	const appPath = "linux-64/" + appFile
	const portablePath = "noarch/" + portableFile
	const index = "linux-64/repodata.json"
	const portableIndex = "noarch/repodata.json"
	members := []string{first, lower}
	mavenRepositories(t, s, owner,
		store.Repository{Name: first, Format: "conda", Access: "restricted", RequireReview: true},
		store.Repository{Name: lower, Format: "conda", Access: "restricted"},
		store.Repository{Name: group, Format: "conda", Mode: "group", Access: "restricted", RequireReview: true, Settings: store.RepositorySettings{Members: members}},
		store.Repository{Name: override, Format: "conda", Mode: "group", Access: "restricted", RequireReview: true,
			Settings: store.RepositorySettings{Members: members, NamespaceOwners: map[string]string{appName + "/": lower}}})
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(ctx, database.OwnerDSN, owner.Tenant, actor, "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := s.DB.Authenticate(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	api := lifecycleHTTP(t, s, token)
	grant := func(repo string, allowed bool) {
		t.Helper()
		key := "cratectl-conda-group-grant-" + repo
		if !allowed {
			key += "-revoke"
		}
		w := api("PUT", "/api/v1/repositories/"+repo+"/grants", map[string]any{"actor": actor, "read": allowed}, key)
		if w.Code != 200 {
			t.Fatal("group grants", repo, w.Code, w.Body.String())
		}
	}
	request := func(repo, cred, method, path string, body []byte, status int, headers ...string) *httptest.ResponseRecorder {
		t.Helper()
		w := nugetHTTP(t, s, cred, method, "/conda/"+repo+"/"+path, body, "", headers...)
		if w.Code != status {
			t.Fatalf("Conda group %s %s/%s returned %d, expected %d: %.250s", method, repo, path, w.Code, status, w.Body.String())
		}
		return w
	}
	fixture := func(name string) []byte {
		t.Helper()
		body, err := os.ReadFile("../conda/testdata/cratectl-conda-" + name + ".tar.bz2")
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	approve := func(repo, path, digest string) {
		t.Helper()
		if err := s.DB.Tx(ctx, owner, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, owner, repo, path, digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	view := func(repo, path string, want map[string]string) string {
		t.Helper()
		w := request(repo, reader, "GET", path, nil, 200)
		var index struct {
			Info struct {
				Subdir  string `json:"subdir"`
				BaseURL string `json:"base_url"`
			} `json:"info"`
			Version int `json:"repodata_version"`
			Records map[string]struct {
				Digest string `json:"sha256"`
			} `json:"packages"`
		}
		subdir, _, _ := strings.Cut(path, "/")
		if err := json.Unmarshal(w.Body.Bytes(), &index); err != nil || index.Version != 2 || index.Info.Subdir != subdir ||
			len(index.Records) != len(want) || index.Records == nil {
			t.Fatalf("invalid Conda platform view for %s: %s (%v)", subdir, w.Body.String(), err)
		}
		for filename, digest := range want {
			if index.Records[filename].Digest != digest {
				t.Fatal("view did not bind original bytes for", filename)
			}
		}
		base, ok := strings.CutPrefix(index.Info.BaseURL, s.PublicURL+"/conda/"+repo+"/"+subdir+"/snapshot/")
		if !ok || len(base) != 65 || !strings.HasSuffix(base, "/") {
			t.Fatal("view did not advertise a local platform snapshot", index.Info.BaseURL)
		}
		return subdir + "/snapshot/" + base
	}
	channel := func() string {
		t.Helper()
		w := request(group, reader, "GET", "snapshot.json", nil, 200)
		var snapshot struct {
			Channel string `json:"channel"`
			Digest  string `json:"sha256"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil || len(snapshot.Digest) != 64 ||
			snapshot.Channel != s.PublicURL+"/conda/"+group+"/snapshots/"+snapshot.Digest+"/" {
			t.Fatal("snapshot discovery did not return the current local channel", err)
		}
		return "snapshots/" + snapshot.Digest + "/"
	}
	for _, repo := range []string{group, override, lower} {
		grant(repo, true)
	}
	baseBytes, preferredBytes, portableBytes := fixture("linux-dependency"), fixture("linux-dependency-other"), fixture("valid")
	baseDigest, preferredDigest, portableDigest := crypt.Digest(baseBytes), crypt.Digest(preferredBytes), crypt.Digest(portableBytes)
	request(lower, token, "PUT", appPath, baseBytes, 201)
	request(lower, token, "PUT", portablePath, portableBytes, 201)
	approve(lower, portablePath, portableDigest)
	request(group, reader, "GET", index, nil, 403)
	grant(first, true)
	view(group, index, nil)
	approve(lower, appPath, baseDigest)
	lowerView := view(group, index, map[string]string{appFile: baseDigest})
	portableView := view(group, portableIndex, map[string]string{portableFile: portableDigest})
	lowerChannel := channel()
	got := request(group, reader, "GET", lowerView+appFile, nil, 200)
	if !bytes.Equal(got.Body.Bytes(), baseBytes) || got.Header().Get("X-Cratectl-Repository") != lower {
		t.Fatal("absence in the preferred member did not preserve the exact lower archive")
	}
	endpoint, err := s.DB.Repository(ctx, identity, group)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.CondaSnapshot{Digest: strings.TrimSuffix(strings.TrimPrefix(lowerView, "linux-64/snapshot/"), "/")}
	entry, source, err := s.DB.CondaGroupArtifact(ctx, identity, group, appPath, snapshot, endpoint.SourceRevision, s.NativeVersionLimit)
	if err != nil {
		t.Fatal(err)
	}
	prior := resolvedArtifact{artifact: entry, source: source, groups: []string{group},
		groupRevisions: map[string]int64{group: endpoint.SourceRevision}, condaGroupView: snapshot}
	request(first, token, "PUT", appPath, preferredBytes, 201)
	view(group, index, nil)
	request(group, reader, "GET", appPath, nil, 404)
	request(group, token, "PUT", appPath, preferredBytes, 405)
	request(group, reader, "GET", lowerView+appFile, nil, 409)
	request(group, reader, "GET", lowerChannel+index, nil, 409)
	if _, err := s.guardResolved(ctx, identity, prior); !errors.Is(err, store.ErrCondaSnapshotChanged) {
		t.Fatal("post-hash admission did not fence the prior owner", err)
	}
	approve(first, appPath, preferredDigest)
	preferredView := view(group, index, map[string]string{appFile: preferredDigest})
	preferredChannel := channel()
	if w := request(group, reader, "GET", preferredChannel+index, nil, 200); !strings.Contains(w.Body.String(), `"repodata_version":1`) ||
		strings.Contains(w.Body.String(), `"base_url"`) || !strings.Contains(w.Body.String(), preferredDigest) {
		t.Fatal("the pinned root did not expose the standard channel index", w.Body.String())
	}
	if w := request(group, reader, "GET", preferredChannel+appPath, nil, 200); !bytes.Equal(w.Body.Bytes(), preferredBytes) {
		t.Fatal("standard pinned channel did not fetch the exact preferred bytes")
	}
	if view(group, "linux-64/current_repodata.json", map[string]string{appFile: preferredDigest}) != preferredView {
		t.Fatal("the two metadata routes did not agree on a snapshot")
	}
	if view(group, portableIndex, map[string]string{portableFile: portableDigest}) != portableView {
		t.Fatal("publication in the native subdirectory changed an independent noarch snapshot")
	}
	got = request(group, reader, "GET", preferredView+appFile, nil, 206, "Range", "bytes=2-8")
	if !bytes.Equal(got.Body.Bytes(), preferredBytes[2:9]) || got.Header().Get("X-Cratectl-Repository") != first {
		t.Fatal("selected range lost the preferred archive binding")
	}
	explicit := view(override, index, map[string]string{appFile: baseDigest})
	if w := request(override, reader, "GET", explicit+appFile, nil, 200); !bytes.Equal(w.Body.Bytes(), baseBytes) {
		t.Fatal("explicit package ownership failed")
	}
	state, err := s.DB.ArtifactState(ctx, owner, first, appPath)
	if err != nil {
		t.Fatal(err)
	}
	retire := store.ArtifactStateRequest{Path: appPath, Digest: preferredDigest, Action: "delete", ExpectedRevision: state.Revision,
		Reason: "Retire the preferred Conda build"}
	if w := api("PUT", "/api/v1/repositories/"+first+"/artifacts/lifecycle", retire, "cratectl-conda-group-retire"); w.Code != 200 {
		t.Fatal("retire preferred Conda build", w.Code, w.Body.String())
	}
	view(group, index, nil)
	request(group, reader, "GET", preferredView+appFile, nil, 409)
	request(group, reader, "GET", preferredChannel+portablePath, nil, 409)
	grant(lower, false)
	request(group, reader, "GET", index, nil, 403)
	request(group, reader, "GET", portableView+portableFile, nil, 403)
}
