//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func exportServerFixture(t *testing.T) (*Server, string, store.Identity, store.GoExportRequest, testdb.Database) {
	t.Helper()
	s, d, token, admin := schemaServer(t)
	mavenRepositories(t, s, admin, store.Repository{Name: "exported", Format: "go", RequireReview: true, Access: "restricted"})
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0"}
	raw, _ := goPublicationFixture(t, c, "owned export API bytes")
	if w := goHTTP(t, s, token, "PUT", "/go/exported/"+c.Prefix()+".zip", raw); w.Code != 201 {
		t.Fatal("owned real-PG publication", w.Code)
	}
	for _, a := range goInventory(t, s, admin, "exported") {
		if err := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(context.Background(), tx, admin, "exported", a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s, token, admin, store.GoExportRequest{Repository: "exported", Module: c.Module, Version: c.Version, LifetimeSeconds: 60}, d
}

func TestGoModuleExportManagementActualHTTPAndResumableCurrentPolicy(t *testing.T) {
	s, token, admin, req, _ := exportServerFixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal("owned export API loopback port unavailable", err)
	}
	ts := httptest.NewUnstartedServer(s)
	ts.Listener.Close()
	ts.Listener = listener
	ts.Start()
	defer ts.Close()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, path string, body any, headers ...string) (int, []byte, http.Header) {
		t.Helper()
		var raw []byte
		if body != nil {
			var err error
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.SetBasicAuth("token", token)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		for n := 0; n < len(headers); n += 2 {
			r.Header.Set(headers[n], headers[n+1])
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal("actual owned HTTP exchange", err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
		if err != nil || len(data) > 4<<20 {
			t.Fatal("bounded API response", err)
		}
		return res.StatusCode, data, res.Header
	}
	if status, _, _ := request("POST", "/api/v1/go/exports/preview", req); status != 200 {
		t.Fatal("current authorized preview", status)
	}
	status, created, _ := request("POST", "/api/v1/go/exports", req, "Idempotency-Key", "native-export-api")
	var v store.GoExportSession
	if status != 201 || json.Unmarshal(created, &v) != nil || v.DeliveryVerified {
		t.Fatal("actual durable API create", status)
	}
	if status, raw, h := request("POST", "/api/v1/go/exports", req, "Idempotency-Key", "native-export-api"); status != 201 || !bytes.Equal(raw, created) || h.Get("Idempotent-Replayed") != "true" {
		t.Fatal("actual API lost-response replay", status)
	}
	path := "/api/v1/go/exports/" + v.ID
	status, manifestRaw, headers := request("GET", path+"/manifest?generation=1", nil)
	m, err := store.ParseGoExportManifest(manifestRaw)
	if status != 200 || err != nil || crypt.Digest(manifestRaw) != v.Manifest.Digest || headers.Get("Cache-Control") != "private, no-store" || m.CurrentRegistryAdmission || m.ChecksumAuthority || m.DependencyClosure {
		t.Fatal("actual immutable manifest download", status, err)
	}
	status, partial, h := request("GET", path+"/zip?generation=1", nil, "Range", "bytes=0-15", "If-Range", `"sha256:`+m.Artifacts[0].Digest+`"`)
	if status != 206 || len(partial) != 16 || h.Get("Content-Range") != "bytes 0-15/"+strconv.FormatInt(m.Artifacts[0].Size, 10) {
		t.Fatal("range resume identity", status)
	}
	if status, raw, h := request("HEAD", path+"/zip?generation=1", nil); status != 200 || len(raw) != 0 || h.Get("Content-Length") != strconv.FormatInt(m.Artifacts[0].Size, 10) {
		t.Fatal("authorized HEAD identity", status)
	}
	if status, _, _ := request("GET", path+"/zip?generation=1", nil, "If-None-Match", `"sha256:`+m.Artifacts[0].Digest+`"`); status != 304 {
		t.Fatal("conditional request", status)
	}
	if err := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error {
		a := m.Artifacts[1]
		_, err := store.Decide(context.Background(), tx, admin, req.Repository, a.Path, a.Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := request("GET", path+"/zip?generation=1", nil, "If-None-Match", `"sha256:`+m.Artifacts[0].Digest+`"`); status != 403 {
		t.Fatal("conditional request bypassed current bundle policy", status)
	}
	if err := s.DB.Tx(context.Background(), admin, true, func(tx pgx.Tx) error {
		a := m.Artifacts[1]
		_, err := store.Decide(context.Background(), tx, admin, req.Repository, a.Path, a.Digest, "allowed")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if status, raw, _ := request("GET", path+"/manifest?generation=1", nil); status != 200 || !bytes.Equal(raw, manifestRaw) {
		t.Fatal("resume rewrote historical source policy", status)
	}
	change := store.GoExportChange{Action: "renew", ExpectedGeneration: 1, LifetimeSeconds: 3600, ManifestSHA256: v.Manifest.Digest}
	if status, _, _ := request("PATCH", path, change, "Idempotency-Key", "native-export-renew"); status != 200 {
		t.Fatal("native current-authorized renewal", status)
	}
	if status, _, _ := request("GET", path+"/zip?generation=1", nil); status != 409 {
		t.Fatal("old generation survived renewal", status)
	}
	if status, raw, _ := request("GET", path+"/zip?generation=2", nil); status != 200 || crypt.Digest(raw) != m.Artifacts[0].Digest {
		t.Fatal("resumed exact immutable bytes", status)
	}
}

type blockedExportWriter struct {
	header           http.Header
	started, aborted chan struct{}
	once, abortOnce  sync.Once
}

func (w *blockedExportWriter) Header() http.Header { return w.header }
func (w *blockedExportWriter) WriteHeader(int)     {}
func (w *blockedExportWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.aborted
	return 0, context.Canceled
}
func (w *blockedExportWriter) SetWriteDeadline(d time.Time) error {
	if !d.IsZero() && !d.After(time.Now()) {
		w.abort()
	}
	return nil
}
func (w *blockedExportWriter) abort() { w.abortOnce.Do(func() { close(w.aborted) }) }

func TestGoModuleExportManagementHeartbeatFencesCancelledTransfer(t *testing.T) {
	s, token, admin, req, _ := exportServerFixture(t)
	raw, _ := json.Marshal(req)
	w := goHTTP(t, s, token, "POST", "/api/v1/go/exports", raw, "Idempotency-Key", "blocked-export")
	var v store.GoExportSession
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal("prepare governed export", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := httptest.NewRequest("GET", "/api/v1/go/exports/"+v.ID+"/zip?generation=1", nil).WithContext(ctx)
	r.SetBasicAuth("token", token)
	blocked := &blockedExportWriter{header: make(http.Header), started: make(chan struct{}), aborted: make(chan struct{})}
	defer blocked.abort()
	done := make(chan struct{})
	go func() { defer close(done); s.ServeHTTP(blocked, r) }()
	select {
	case <-blocked.started:
	case <-ctx.Done():
		t.Fatal("owned response-writer stand-in did not block after admission")
	}
	select {
	case <-blocked.aborted:
		t.Fatal("transfer ended before cancellation")
	default:
	}
	if _, err := s.DB.ChangeGoExport(context.Background(), admin, v.ID, store.GoExportChange{Action: "cancel", ExpectedGeneration: 1, ManifestSHA256: v.Manifest.Digest}, "cancel-blocked-export"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("current SQL fence did not interrupt the blocked transfer")
	}
	if _, err := s.DB.GoExportObject(context.Background(), admin, v.ID, 2, "zip"); !errors.Is(err, store.ErrGoExportExpired) {
		t.Fatal("cancelled transfer reopened", err)
	}
}
