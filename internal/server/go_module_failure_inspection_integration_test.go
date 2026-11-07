//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleChecksumManagementDownloadsExactEvidenceWithCurrentAuthorization(t *testing.T) {
	s, d, admin, i := schemaServer(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../store/testdata/go-checksum-timeline-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Module    string                `json:"module"`
		Key       string                `json:"verifier_key"`
		One       []byte                `json:"first_checkpoint"`
		ZIPHashes map[string]string     `json:"zip_h1"`
		ModHash   string                `json:"mod_h1"`
		Fork      crypt.GoSumDBSnapshot `json:"fork"`
	}
	if err = json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	repo := goChecksumCallerRepository(t, s, i, "http://127.0.0.1:38443", publicGoChecksum{Key: log.Key, Initial: log.One}, false)
	c := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
	lease, err := s.DB.AcquireRetrieval(ctx, i, repo.Name, c.Prefix()+".zip", "management-failure", false)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	report := store.GoChecksumFailureReport{Profile: store.GoChecksumFailureProfile, Module: c.Module, Version: c.Version, ZIPHash: log.ZIPHashes[c.Version], ModHash: log.ModHash, VerifierKey: log.Key, Checkpoint: log.One}
	for path, body := range log.Fork.Responses {
		report.Attempts = append(report.Attempts, store.GoChecksumFailureAttempt{Path: path, Status: 200, Code: "ok", Body: body})
	}
	if err = s.DB.CompleteRetrieval(ctx, i, lease, store.RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &store.GoChecksumFailure{Report: report}}); err != nil {
		t.Fatal(err)
	}
	original, digest, err := s.DB.GoChecksumFailureEvidence(ctx, i, repo.Name, lease.Path, 0, lease.Generation)
	if err != nil {
		t.Fatal(err)
	}
	request := func(token, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	base := "/api/v1/repositories/" + repo.Name + "/go/checksum"
	state := request(admin, base+"?source_revision=0")
	if state.Code != 200 || !strings.Contains(state.Body.String(), `"blocked":true`) || !strings.Contains(state.Body.String(), `"package_admission":false`) || strings.Contains(state.Body.String(), c.Module) {
		t.Fatal("safe current state", state.Code, state.Body.String())
	}
	page := request(admin, base+"/failures?limit=1")
	var history struct {
		Items []store.GoChecksumFailureSummary `json:"items"`
		More  bool                             `json:"more"`
	}
	if page.Code != 200 || json.Unmarshal(page.Body.Bytes(), &history) != nil || len(history.Items) != 1 || history.More || history.Items[0].EvidenceDigest != digest || bytes.Contains(page.Body.Bytes(), []byte("attempts")) {
		t.Fatal("bounded failure summary", page.Code, page.Body.String())
	}
	evidenceURL := base + "/failures/evidence?" + url.Values{"root_path": {lease.Path}, "source_revision": {"0"}, "generation": {strconv.FormatInt(lease.Generation, 10)}}.Encode()
	download := request(admin, evidenceURL)
	if download.Code != 200 || !bytes.Equal(download.Body.Bytes(), original) || download.Header().Get("X-Cratectl-Evidence-SHA256") != digest || download.Header().Get("Content-Length") != strconv.Itoa(len(original)) || download.Header().Get("Cache-Control") != "private, no-store" || download.Header().Get("Content-Disposition") != `attachment; filename="go-checksum-failure.json"` {
		t.Fatal("download changed exact immutable evidence or permitted caching", download.Code)
	}
	if record, err := store.VerifyGoChecksumFailureEvidence(ctx, download.Body.Bytes(), log.Key); err != nil || record.Classification != "fork" {
		t.Fatal("download does not verify offline", err)
	}
	reader, _ := crypt.Token()
	other, _ := crypt.Token()
	for _, v := range []struct{ tenant, actor, role, token string }{{i.Tenant, "inspection-reader", "reader", reader}, {"unrelated-inspection", "operator", "admin", other}} {
		if err = store.Provision(ctx, d.OwnerDSN, v.tenant, v.actor, v.role, v.token, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,$2,'inspection-reader',true,false)`, i.Tenant, repo.Name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w := request(reader, base+"?source_revision=0"); w.Code != 200 || !strings.Contains(w.Body.String(), `"blocked":true`) {
		t.Fatal("reader could not inspect safe key state", w.Code)
	}
	for _, path := range []string{base + "/failures", evidenceURL} {
		if w := request(reader, path); w.Code != 403 || bytes.Contains(w.Body.Bytes(), original) {
			t.Fatal("ordinary repo read grant exposed upstream failure data", w.Code)
		}
		if w := request(other, path); w.Code != 404 || strings.Contains(w.Body.String(), c.Module) || bytes.Contains(w.Body.Bytes(), []byte(digest)) {
			t.Fatal("cross-tenant incident data leaked", w.Code)
		}
	}
	if w := request("", evidenceURL); w.Code != 401 {
		t.Fatal("anonymous evidence download", w.Code)
	}
	if _, err = s.DB.ChangeRepositoryState(ctx, i, repo.Name, "inspection-suspend", "inspection-suspend", store.RepositoryStateRequest{Action: "suspend", Reason: "preserve evidence during incident review"}, 100); err != nil {
		t.Fatal(err)
	}
	if w := request(admin, evidenceURL); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), original) {
		t.Fatal("suspension hid historical incident evidence", w.Code)
	}
	// Recheck current credential validity on every inspection, including downloads.
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if _, err = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET expires_at='epoch' WHERE hash=$1`, crypt.Digest([]byte(admin))); err != nil {
		t.Fatal(err)
	}
	if w := request(admin, evidenceURL); w.Code != 401 || bytes.Contains(w.Body.Bytes(), original) {
		t.Fatal("expired administrator downloaded retained sensitive bodies", w.Code)
	}
}
