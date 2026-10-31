//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/worker"
	"github.com/jackc/pgx/v5"
)

func TestRetentionHTTPWorkerResumesApprovedTargetsAndNativeRestorePreservesBytes(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	ctx := context.Background()
	api := lifecycleHTTP(t, s, token)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "retained", "format": "oci"}, "retention-repo"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	digests := []string{}
	for _, label := range []string{"old-a", "old-b", "latest"} {
		digests = append(digests, lifecyclePublish(t, s, token, "retained", label))
		time.Sleep(time.Millisecond)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `UPDATE cratectl.artifacts SET created_at=created_at-interval '1 hour' WHERE tenant=$1 AND repository='retained'`, admin.Tenant); e != nil {
		t.Fatal(e)
	}
	policyPath := "/api/v1/repositories/retained/retention-policies/age"
	input := store.RetentionPolicyRequest{RetentionSettings: store.RetentionSettings{MinAgeSeconds: 60, KeepLast: 1, ProtectTagged: false, Enabled: true, Reason: "Retire old OCI manifests while retaining the newest"}}
	input.DryRun = true
	if w := api("PUT", policyPath, input, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", policyPath, nil, ""); w.Code != 404 {
		t.Fatal("preview wrote policy", w.Code)
	}
	input.DryRun = false
	created := api("PUT", policyPath, input, "retention-policy")
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	if w := api("PUT", policyPath, input, "retention-policy"); w.Code != 200 || w.Header().Get("Idempotent-Replayed") != "true" || w.Body.String() != created.Body.String() {
		t.Fatal("configuration replay", w.Code, w.Body.String())
	}
	run := store.RetentionRequest{ExpectedRevision: 1, Reason: "Explicit reviewed retirement", DryRun: true}
	preview := api("POST", policyPath+"/runs", run, "")
	if preview.Code != 200 {
		t.Fatal(preview.Code, preview.Body.String())
	}
	var plan store.RetentionPlan
	if json.Unmarshal(preview.Body.Bytes(), &plan) != nil || plan.Eligible != 2 || plan.Targets != 3 {
		t.Fatal(preview.Body.String())
	}
	run.DryRun = false
	run.EvaluatedAt = &plan.EvaluatedAt
	run.PreviewDigest = plan.Digest
	admitted := api("POST", policyPath+"/runs", run, "retention-run")
	if admitted.Code != 202 {
		t.Fatal(admitted.Code, admitted.Body.String())
	}
	var response struct {
		Job string `json:"job"`
	}
	if json.Unmarshal(admitted.Body.Bytes(), &response) != nil {
		t.Fatal(admitted.Body.String())
	}
	if w := api("POST", policyPath+"/runs", run, "retention-run"); w.Code != 202 || w.Body.String() != admitted.Body.String() || w.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("admission replay", w.Code, w.Body.String())
	}
	workerToken, _ := crypt.Token()
	if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, "retention-worker", "worker", workerToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	identity, e := s.DB.AuthenticateWorker(ctx, workerToken)
	if e != nil {
		t.Fatal(e)
	}
	runWorker := func(stopAfterOne bool) {
		work, cancel := context.WithCancel(ctx)
		defer cancel()
		options := worker.Options{Name: "retention-http", Identities: []store.WorkerIdentity{identity}, EventConcurrency: 1, IntegrityConcurrency: 1, MaintenanceConcurrency: 1, Lease: 3 * time.Second, Poll: 10 * time.Millisecond, Timeout: 5 * time.Second, MaxObjectBytes: 1 << 20, MaxEventBytes: 1 << 20}
		options.Notice = func(n worker.Notice) {
			if n.Job == response.Job && ((stopAfterOne && n.State == "pending") || n.State == "succeeded") {
				cancel()
			}
		}
		timeout := time.AfterFunc(8*time.Second, cancel)
		defer timeout.Stop()
		if e := worker.Run(work, s.DB, s.Blobs, options); e != nil {
			t.Fatal(e)
		}
	}
	runWorker(true)
	progress, e := s.DB.RetentionRun(ctx, admin, response.Job)
	if e != nil || progress["processed"] != int64(1) {
		t.Fatal("first worker checkpoint", progress, e)
	}
	runWorker(false)
	progress, e = s.DB.RetentionRun(ctx, admin, response.Job)
	if e != nil || progress["all_targets_processed"] != true || progress["retired"] != int64(2) {
		t.Fatal(progress, e)
	}
	for _, digest := range digests[:2] {
		if w := api("GET", "/v2/retained/app/manifests/sha256:"+digest, nil, ""); w.Code != 404 || !strings.Contains(w.Body.String(), "artifact_deleted") {
			t.Fatal("native retired manifest remained visible", w.Code, w.Body.String())
		}
		file, e := s.Blobs.Open(admin.Tenant, digest)
		if e != nil {
			t.Fatal("retained bytes disappeared", e)
		}
		data, e := io.ReadAll(file)
		file.Close()
		if e != nil || crypt.Digest(data) != digest {
			t.Fatal("retirement changed bytes", e)
		}
	}
	restore := map[string]any{"path": "app/manifests/sha256:" + digests[0], "digest": digests[0], "action": "restore", "expected_revision": 1, "reason": "Recover exact retained bytes"}
	if w := api("PUT", "/api/v1/repositories/retained/artifacts/lifecycle", restore, "retention-restore"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", "/v2/retained/app/manifests/sha256:"+digests[0], nil, ""); w.Code != 200 || crypt.Digest(w.Body.Bytes()) != digests[0] {
		t.Fatal("native restore", w.Code, w.Body.String())
	}
	if w := api("GET", "/v2/retained/app/manifests/latest", nil, ""); w.Code != 200 || crypt.Digest(w.Body.Bytes()) != digests[2] {
		t.Fatal("restore rebound the current tag", w.Code, w.Body.String())
	}
	for _, path := range []string{policyPath, policyPath + "/history?limit=1", policyPath + "/runs?limit=1", "/api/v1/repositories/retained/retention-policies?limit=1", "/api/v1/maintenance/retention-runs/" + response.Job, "/api/v1/maintenance/retention-runs/" + response.Job + "/items?limit=2"} {
		w := api("GET", path, nil, "")
		if w.Code != 200 || strings.Contains(w.Body.String(), admin.CredentialHash) || strings.Contains(w.Body.String(), token) {
			t.Fatal("inspection or execution fence exposure", path, w.Code)
		}
	}
	if w := api("GET", policyPath+"/runs?limit=1&limit=2", nil, ""); w.Code != 400 {
		t.Fatal("duplicate query", w.Code)
	}
	readerToken, _ := crypt.Token()
	if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, "reader", "reader", readerToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if w := lifecycleHTTP(t, s, readerToken)("GET", policyPath, nil, ""); w.Code != 403 {
		t.Fatal("reader retention access", w.Code)
	}
	if w := lifecycleHTTP(t, s, workerToken)("GET", policyPath, nil, ""); w.Code != 401 {
		t.Fatal("worker entered public API", w.Code)
	}
}
