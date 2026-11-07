//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleRequirementExportActualHTTPOriginalMetadataRangeReplayAndCurrentFence(t *testing.T) {
	s, token, admin, one, _ := exportServerFixture(t)
	r := goRequirementRequest{Repository: one.Repository, MainGoMod: "module owned/main\ngo 1.27.0\nrequire " + one.Module + " " + one.Version + "\n", LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20}
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s)
	ts.Listener.Close()
	ts.Listener = listener
	ts.Start()
	defer ts.Close()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path string, body any, headers ...string) (int, []byte, http.Header) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("token", token)
		for n := 0; n < len(headers); n += 2 {
			req.Header.Set(headers[n], headers[n+1])
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err = io.ReadAll(io.LimitReader(res.Body, store.MaxGoRequirementExportManifest+1))
		if err != nil || len(raw) > store.MaxGoRequirementExportManifest {
			t.Fatal("unbounded graph response", err)
		}
		return res.StatusCode, raw, res.Header
	}
	const endpoint = "/api/v1/go/export-sets/requirements"
	code, receipt, _ := call("POST", endpoint, r, "Idempotency-Key", "http-requirement-original")
	var v store.GoRequirementExportSession
	if code != 201 || json.Unmarshal(receipt, &v) != nil || v.Profile != store.GoRequirementExportProfile || v.RootCount != 1 || v.SourceCount != 1 || v.Manifest == v.SelectionManifest || v.DeliveryVerified {
		t.Fatal("complete actual HTTP graph creation", code)
	}
	path := endpoint + "/" + v.ID
	code, raw, _ := call("GET", path+"/manifest?generation=1", nil)
	parent, err := store.ParseGoRequirementExportManifest(raw)
	if code != 200 || err != nil || crypt.Digest(raw) != v.Manifest.Digest || parent.Selection.DependencyClosure || parent.Selection.ChecksumAuthority || parent.Selection.CurrentRegistryAdmission {
		t.Fatal("original graph parent", code, err)
	}
	for suffix, object := range map[string]blob.Object{"/main": v.MainGoMod, "/proof": v.RequirementProof, "/selection": v.SelectionManifest, "/inputs/0/manifest": parent.Sources[0].Manifest, "/inputs/0/mod": parent.Sources[0].Mod} {
		code, raw, h := call("GET", path+suffix+"?generation=1", nil)
		if code != 200 || int64(len(raw)) != object.Size || crypt.Digest(raw) != object.Digest || h.Get("Cache-Control") != "private, no-store" {
			t.Fatal("original metadata identity", suffix, code)
		}
	}
	if code, raw, _ := call("GET", path+"/main?generation=1", nil, "Range", "bytes=0-7"); code != 206 || !bytes.Equal(raw, []byte(r.MainGoMod)[:8]) {
		t.Fatal("resumable main metadata range", code)
	}
	if code, raw, h := call("HEAD", path+"/main?generation=1", nil); code != 200 || len(raw) != 0 || h.Get("ETag") != `"sha256:`+v.MainGoMod.Digest+`"` {
		t.Fatal("current metadata HEAD", code)
	}
	if code, _, _ := call("GET", path+"/main?generation=1", nil, "If-None-Match", `"sha256:`+v.MainGoMod.Digest+`"`); code != 304 {
		t.Fatal("current metadata conditional read", code)
	}
	a := parent.Selection.Entries[0].Artifacts[0]
	if err := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error {
		_, err := store.Decide(context.Background(), tx, admin, one.Repository, a.Path, a.Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := call("GET", path+"/main?generation=1", nil, "If-None-Match", `"sha256:`+v.MainGoMod.Digest+`"`); code != 403 {
		t.Fatal("304 bypassed graph current policy", code)
	}
	if code, raw, h := call("POST", endpoint, r, "Idempotency-Key", "http-requirement-original"); code != 201 || !bytes.Equal(receipt, raw) || h.Get("Idempotent-Replayed") != "true" {
		t.Fatal("original receipt replay re-inspected denied payload or changed bytes", code)
	}
	control := store.GoExportChange{Action: "cancel", ExpectedGeneration: 1, ManifestSHA256: v.SelectionManifest.Digest}
	if code, _, _ := call("POST", "/api/v1/go/export-sets/"+v.ID+"/control", control, "Idempotency-Key", "http-graph-cancel"); code != 200 {
		t.Fatal("cancel denied graph through shared lifecycle", code)
	}
	if code, _, _ := call("GET", path+"/manifest?generation=2", nil); code != 410 {
		t.Fatal("terminal graph delivered metadata", code)
	}
}

func TestGoModuleRequirementExportMissingPhysicalSelectedPayloadCommitsNoGraph(t *testing.T) {
	s, token, admin, one, _ := exportServerFixture(t)
	ctx := context.Background()
	p, err := s.DB.PlanGoExport(ctx, admin, one)
	if err != nil {
		t.Fatal(err)
	}
	o := p.Objects()[0]
	file, err := s.Blobs.OpenVerified(ctx, admin.Tenant, o.Digest, o.Size)
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	file.Close()
	missing := path + ".owned-requirement-zip-missing"
	if err := os.Rename(path, missing); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(missing, path); err != nil {
			t.Error(err)
		}
	}()
	counts := func() [5]int {
		t.Helper()
		var out [5]int
		if err := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.artifact_export_sets),(SELECT count(*) FROM cratectl.artifact_export_set_requirements),(SELECT count(*) FROM cratectl.events),(SELECT count(*) FROM cratectl.jobs),(SELECT count(*) FROM cratectl.mutations)`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4])
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := counts()
	raw, _ := json.Marshal(goRequirementRequest{Repository: one.Repository, MainGoMod: "module owned/main\ngo 1.27.0\nrequire " + one.Module + " " + one.Version + "\n", LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20})
	response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/requirements", raw, "Idempotency-Key", "missing-graph-zip")
	if response.Code == 201 || response.Code == 200 || counts() != before {
		t.Fatal("missing physical selected ZIP committed graph references/receipt/event/job", response.Code)
	}
}
