//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleLegacyChecksumManagementReviewRecoveryAndCurrentCredentials(t *testing.T) {
	s, d, admin, i := schemaServer(t)
	ctx := context.Background()
	log := goChecksumPublic(t)
	repo := goChecksumCallerRepository(t, s, i, "http://127.0.0.1:38443", log, false)
	c, err := gomodule.Canonical(log.Module, log.Version)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.DB.AcquireRetrieval(ctx, i, repo.Name, c.Prefix()+".zip", "legacy-management-label", false)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	if err = s.DB.CompleteRetrieval(ctx, i, lease, store.RetrievalResult{Failure: "upstream_checksum_fork"}); err != nil {
		t.Fatal(err)
	}
	page, _, err := s.DB.GoChecksumLegacyIncidentPage(ctx, i, 0, 25, "")
	if err != nil || len(page) != 1 {
		t.Fatal(err)
	}
	incident := page[0]
	state, err := s.DB.GoChecksumState(ctx, i, repo.Name, 0)
	if err != nil || state.Blocked || !state.LegacyReviewRequired {
		t.Fatal(err)
	}
	api := lifecycleHTTP(t, s, admin)
	base := "/api/v1/go/checksum/legacy-incidents"
	item := base + "/" + strconv.FormatInt(incident.Sequence, 10)
	reviewPath := item + "/reviews"
	if w := api("GET", base+"?limit=1&key_digest="+state.Checkpoint.KeyDigest, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"reviewed_for_key":false`) || strings.Contains(w.Body.String(), c.Module) {
		t.Fatal("bounded unattributed incident page", w.Code, w.Body.String())
	}
	if w := api("GET", item, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"unattributed_fork_label"`) || !strings.Contains(w.Body.String(), incident.EventHash) || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("original incident inspection", w.Code)
	}
	input := legacyChecksumReviewInput{Repository: repo.Name, GoChecksumLegacyReviewRequest: store.GoChecksumLegacyReviewRequest{DryRun: true, IncidentHash: incident.EventHash, KeyDigest: state.Checkpoint.KeyDigest, CheckpointSHA256: state.CheckpointSHA256, ReviewReferenceSHA256: crypt.Digest([]byte("owned external review document")), Reason: "Explicit external trust decision despite missing old proof"}}
	if w := api("POST", reviewPath, input, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"package_admission":false`) {
		t.Fatal("read-only impact preview", w.Code, w.Body.String())
	}
	if current, err := s.DB.GoChecksumState(ctx, i, repo.Name, 0); err != nil || !current.LegacyReviewRequired {
		t.Fatal("preview mutated admission", err)
	}
	input.DryRun = false
	if w := api("POST", reviewPath, input, "legacy-no-ack"); w.Code != 400 {
		t.Fatal("apply inferred missing explicit acknowledgment", w.Code)
	}
	input.AcceptUnattributedHistory = true
	first := api("POST", reviewPath, input, "legacy-management-review")
	if first.Code != 200 || !strings.Contains(first.Body.String(), `"package_admission":false`) {
		t.Fatal("explicit incident review", first.Code, first.Body.String())
	}
	if w := api("POST", reviewPath, input, "legacy-management-review"); w.Code != 200 || w.Header().Get("Idempotent-Replayed") != "true" || !bytes.Equal(w.Body.Bytes(), first.Body.Bytes()) {
		t.Fatal("lost response replay lost exact review receipt", w.Code)
	}
	changed := input
	changed.Reason = "different reason"
	if w := api("POST", reviewPath, changed, "legacy-management-review"); w.Code != 409 {
		t.Fatal("changed body reused idempotency identity", w.Code)
	}
	if w := api("GET", reviewPath+"?key_digest="+input.KeyDigest, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"verifier_key"`) || !strings.Contains(w.Body.String(), input.ReviewReferenceSHA256) {
		t.Fatal("retained review/trust outcome", w.Code)
	}
	if current, err := s.DB.GoChecksumState(ctx, i, repo.Name, 0); err != nil || current.LegacyReviewRequired || current.Blocked || current.Checkpoint.Revision != 0 || !bytes.Equal(current.Checkpoint.Checkpoint, state.Checkpoint.Checkpoint) {
		t.Fatal("review rewrote checkpoint or approved a fork", err)
	}
	if _, err = s.DB.GoModuleChecksumReadback(ctx, i, repo.Name, c, 0); err == nil {
		t.Fatal("operator review alone approved failed module bytes")
	}
	reader, _ := crypt.Token()
	other, _ := crypt.Token()
	for _, v := range []struct{ tenant, actor, role, token string }{{i.Tenant, "legacy-reader", "reader", reader}, {"unrelated-legacy", "operator", "admin", other}} {
		if err = store.Provision(ctx, d.OwnerDSN, v.tenant, v.actor, v.role, v.token, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,$2,'legacy-reader',true,false)`, i.Tenant, repo.Name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, item, reviewPath + "?key_digest=" + input.KeyDigest} {
		if w := lifecycleHTTP(t, s, reader)("GET", path, nil, ""); w.Code != 403 || strings.Contains(w.Body.String(), incident.EventHash) {
			t.Fatal("reader grant exposed global incident/review", w.Code)
		}
	}
	if w := lifecycleHTTP(t, s, reader)("POST", reviewPath, input, "legacy-management-review"); w.Code != 403 {
		t.Fatal("reader replay bypassed current administrator requirement", w.Code)
	}
	if w := lifecycleHTTP(t, s, other)("GET", item, nil, ""); w.Code != 404 || strings.Contains(w.Body.String(), incident.EventHash) {
		t.Fatal("cross-tenant incident disclosure", w.Code)
	}
	if w := lifecycleHTTP(t, s, other)("GET", base, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("cross-tenant incident inventory", w.Code)
	}
	// A replacement is an authorized configuration change, never a new proxy.
	next := repo.Settings
	endpoint := next.GoChecksumAuthority.Endpoint
	endpoint.CredentialRef = "legacy-checksum-reference"
	endpoint.Authentication = "bearer"
	a := *next.GoChecksumAuthority
	a.Endpoint = endpoint
	next.GoChecksumAuthority = &a
	configuration := store.ConfigurationRequest{ExpectedRevision: 0, Settings: &next, Reason: "revalidate checksum endpoint credential authority"}
	s.UpstreamCredentials[i.Tenant+"/legacy-checksum-reference"] = UpstreamCredential{Value: "owned-checksum-credential-fixture", AllowedURL: "http://127.0.0.1:38443/different/"}
	configPath := "/api/v1/repositories/" + repo.Name + "/configuration"
	if w := api("PUT", configPath, configuration, "wrong-checksum-authority"); w.Code != 400 || !strings.Contains(w.Body.String(), "upstream_credential_authority") {
		t.Fatal("checksum credential crossed exact authority", w.Code)
	}
	s.UpstreamCredentials[i.Tenant+"/legacy-checksum-reference"] = UpstreamCredential{Value: "owned-checksum-credential-fixture", AllowedURL: endpoint.URL}
	if w := api("PUT", configPath, configuration, "same-key-new-source"); w.Code != 200 {
		t.Fatal("retained proxy configuration recovery", w.Code, w.Body.String())
	}
	if w := api("GET", reviewPath+"?key_digest="+input.KeyDigest, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"source_revision":0`) {
		t.Fatal("source change rewrote retained outcome", w.Code)
	}
	if w := api("POST", reviewPath, input, "new-stale-review"); w.Code != 409 {
		t.Fatal("stale source review admitted", w.Code)
	}
	if _, err = s.DB.ChangeRepositoryState(ctx, i, repo.Name, "legacy-inspection-suspend", "legacy-inspection-suspend", store.RepositoryStateRequest{Action: "suspend", Reason: "retain incident context during recovery"}, 100); err != nil {
		t.Fatal(err)
	}
	if w := api("GET", reviewPath+"?key_digest="+input.KeyDigest, nil, ""); w.Code != 200 {
		t.Fatal("suspension hid immutable review", w.Code)
	}
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if _, err = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET expires_at='epoch' WHERE hash=$1`, crypt.Digest([]byte(admin))); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, item, reviewPath + "?key_digest=" + input.KeyDigest} {
		if w := api("GET", path, nil, ""); w.Code != 401 || strings.Contains(w.Body.String(), incident.EventHash) {
			t.Fatal("expired administrator retained evidence access", w.Code)
		}
	}
	if w := api("POST", reviewPath, input, "legacy-management-review"); w.Code != 401 {
		t.Fatal("expired administrator replayed review mutation", w.Code)
	}
}
