//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func exportSetServerFixture(t *testing.T) (*Server, string, store.Identity, store.GoExportSetRequest) {
	t.Helper()
	s, token, admin, first, _ := exportServerFixture(t)
	second := gomodule.Coordinate{Module: first.Module, Version: "v1.1.0"}
	zip, _ := goPublicationFixture(t, second, "original second physical set bytes")
	if w := goHTTP(t, s, token, "PUT", "/go/"+first.Repository+"/"+second.Prefix()+".zip", zip); w.Code != 201 {
		t.Fatal("second actual package intake", w.Code)
	}
	for _, a := range goInventory(t, s, admin, first.Repository) {
		if err := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(context.Background(), tx, admin, first.Repository, a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s, token, admin, store.GoExportSetRequest{Entries: []store.GoExportSetEntry{{Repository: first.Repository, Module: first.Module, Version: first.Version}, {Repository: first.Repository, Module: second.Module, Version: second.Version}}, LifetimeSeconds: 60, MaxArtifactBytes: 1 << 30}
}
func TestGoModuleExportSetActualHTTPPhysicalBytesRangesPolicyAndReceiptReplay(t *testing.T) {
	s, token, admin, request := exportSetServerFixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal("owned export-set socket", err)
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
		r, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.SetBasicAuth("token", token)
		for n := 0; n < len(headers); n += 2 {
			r.Header.Set(headers[n], headers[n+1])
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("actual export-set HTTP", err)
		}
		defer response.Body.Close()
		got, err := io.ReadAll(io.LimitReader(response.Body, store.MaxGoExportSetManifest+1))
		if err != nil || len(got) > store.MaxGoExportSetManifest {
			t.Fatal("bounded export-set body", err)
		}
		return response.StatusCode, got, response.Header
	}
	code, receipt, _ := call("POST", "/api/v1/go/export-sets", request, "Idempotency-Key", "http-set-create")
	var v store.GoExportSetSession
	if code != 201 || json.Unmarshal(receipt, &v) != nil || v.RootCount != 2 || v.Generation != 1 || v.DeliveryVerified || !v.PayloadPinsRetained {
		t.Fatal("complete actual create", code)
	}
	path := "/api/v1/go/export-sets/" + v.ID
	code, raw, headers := call("GET", path+"/manifest?generation=1", nil)
	m, err := store.ParseGoExportSetManifest(raw)
	if code != 200 || err != nil || crypt.Digest(raw) != v.Manifest.Digest || len(m.Entries) != 2 || headers.Get("Cache-Control") != "private, no-store" || m.DependencyClosure || m.CurrentRegistryAdmission || m.ChecksumAuthority {
		t.Fatal("common original manifest", code, err)
	}
	for n, entry := range m.Entries {
		for k, kind := range []string{"zip", "mod", "info"} {
			code, raw, _ := call("GET", fmt.Sprintf("%s/roots/%d/%s?generation=1", path, n, kind), nil)
			if code != 200 || crypt.Digest(raw) != entry.Artifacts[k].Digest {
				t.Fatal("exact original physical representation", n, kind, code)
			}
		}
	}
	zipPath := path + "/roots/1/zip?generation=1"
	etag := `"sha256:` + m.Entries[1].Artifacts[0].Digest + `"`
	if code, raw, h := call("GET", zipPath, nil, "Range", "bytes=0-15", "If-Range", etag); code != 206 || len(raw) != 16 || h.Get("Content-Range") != "bytes 0-15/"+strconv.FormatInt(m.Entries[1].Artifacts[0].Size, 10) {
		t.Fatal("range binding", code)
	}
	if code, raw, h := call("HEAD", zipPath, nil); code != 200 || len(raw) != 0 || h.Get("Content-Length") != strconv.FormatInt(m.Entries[1].Artifacts[0].Size, 10) {
		t.Fatal("HEAD binding", code)
	}
	if code, _, _ := call("GET", zipPath, nil, "If-None-Match", etag); code != 304 {
		t.Fatal("current conditional", code)
	}
	renew := store.GoExportChange{Action: "renew", ExpectedGeneration: 1, LifetimeSeconds: 3600, ManifestSHA256: v.Manifest.Digest}
	if code, _, _ := call("POST", path+"/control", renew, "Idempotency-Key", "http-set-renew"); code != 200 {
		t.Fatal("current renew", code)
	}
	if code, _, _ := call("GET", zipPath, nil); code != 409 {
		t.Fatal("stale generation survived", code)
	}
	late := m.Entries[1].Artifacts[0]
	if err := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error {
		_, err := store.Decide(context.Background(), tx, admin, m.Entries[1].Repository, late.Path, late.Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := call("GET", path+"/roots/0/zip?generation=2", nil, "If-None-Match", `"sha256:`+m.Entries[0].Artifacts[0].Digest+`"`); code != 403 {
		t.Fatal("late denied member did not fence first/conditional", code)
	}
	if code, raw, h := call("POST", "/api/v1/go/export-sets", request, "Idempotency-Key", "http-set-create"); code != 201 || !bytes.Equal(raw, receipt) || h.Get("Idempotent-Replayed") != "true" {
		t.Fatal("historical receipt replay changed or re-inspected denied bytes", code)
	}
	cancel := store.GoExportChange{Action: "cancel", ExpectedGeneration: 2, ManifestSHA256: v.Manifest.Digest}
	if code, _, _ := call("POST", path+"/control", cancel, "Idempotency-Key", "http-set-cancel"); code != 200 {
		t.Fatal("cancel denied source selection", code)
	}
	if code, _, _ := call("GET", path+"/manifest?generation=3", nil); code != 410 {
		t.Fatal("terminal manifest served", code)
	}
}
func TestGoModuleExportSetPhysicalLateFailureCreatesNoDurableSet(t *testing.T) {
	s, token, admin, request := exportSetServerFixture(t)
	ctx := context.Background()
	p, err := s.DB.PlanGoExportSet(ctx, admin, request)
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.ParseGoExportSetManifest(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	late := m.Entries[1].Artifacts[0]
	f, err := s.Blobs.OpenVerified(ctx, admin.Tenant, late.Digest, late.Size)
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	missing := path + ".owned-test-missing"
	if err := os.Rename(path, missing); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(missing, path); err != nil {
			t.Error("restore owned original", err)
		}
	}()
	counts := func() [6]int {
		t.Helper()
		var result [6]int
		if err := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.artifact_export_sets),(SELECT count(*) FROM cratectl.artifact_export_set_roots),(SELECT count(*) FROM cratectl.artifact_export_set_items),(SELECT count(*) FROM cratectl.events),(SELECT count(*) FROM cratectl.jobs),(SELECT count(*) FROM cratectl.mutations)`).Scan(&result[0], &result[1], &result[2], &result[3], &result[4], &result[5])
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := counts()
	raw, _ := json.Marshal(request)
	response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets", raw, "Idempotency-Key", "missing-last-physical-member")
	if response.Code == 201 || response.Code == 200 || bytes.Contains(response.Body.Bytes(), []byte(`"manifest":`)) {
		t.Fatal("missing late physical member certified", response.Code)
	}
	if after := counts(); after != before {
		t.Fatal("physical failure left partial durable references/journal/receipt/job", before, after)
	}
}
