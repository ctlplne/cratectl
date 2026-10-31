//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/worker"
	"github.com/jackc/pgx/v5"
)

func TestRetentionScheduleHTTPExplicitAuthorityAndWorkerFences(t *testing.T) {
	for _, mode := range []string{"complete_restore", "pause_pending"} {
		t.Run(mode, func(t *testing.T) {
			s, d, token, admin := schemaServer(t)
			ctx := context.Background()
			api := lifecycleHTTP(t, s, token)
			if v := api("POST", "/api/v1/repositories", map[string]string{"name": "retained", "format": "oci"}, "schedule-http-repo"); v.Code != 201 {
				t.Fatal("repository", v.Code)
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
			path := policyPath + "/schedule"
			policy := store.RetentionPolicyRequest{RetentionSettings: store.RetentionSettings{MinAgeSeconds: 60, KeepLast: 1, ProtectTagged: true, Enabled: true, Reason: "Retain current release"}}
			if mode == "pause_pending" {
				policy.KeepLast = 0
				policy.ProtectTagged = false
			}
			if v := api("PUT", policyPath, policy, "schedule-http-policy"); v.Code != 200 {
				t.Fatal("policy", v.Code)
			}
			r := store.RetentionScheduleRequest{RetentionScheduleSettings: store.RetentionScheduleSettings{IntervalSeconds: 60, MaxTargets: 100, Enabled: true, Reason: "Explicitly approve future bounded retirement"}, ExpectedPolicyRevision: 1, AuthorizeFutureRetirements: true, RunImmediately: true, DryRun: true}
			raw, _ := json.Marshal(r)
			var missing map[string]any
			_ = json.Unmarshal(raw, &missing)
			delete(missing, "authorize_future_retirements")
			if v := api("PUT", path, missing, ""); v.Code != 400 {
				t.Fatal("missing future authority accepted", v.Code)
			}
			absent := r
			absent.AuthorizeFutureRetirements = false
			if v := api("PUT", path, absent, ""); v.Code != 400 {
				t.Fatal("implicit future authority accepted", v.Code)
			}
			duplicate := strings.TrimSuffix(string(raw), "}") + `,"enabled":false}`
			request := httptest.NewRequest("PUT", path, strings.NewReader(duplicate))
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			reply := httptest.NewRecorder()
			s.ServeHTTP(reply, request)
			if reply.Code != 400 {
				t.Fatal("duplicate schedule field accepted", reply.Code)
			}
			if v := api("PUT", path, r, ""); v.Code != 200 {
				t.Fatal("configuration preview", v.Code, v.Body.String())
			}
			if v := api("GET", path, nil, ""); v.Code != 404 {
				t.Fatal("preview admitted future authority", v.Code)
			}
			r.DryRun = false
			created := api("PUT", path, r, "schedule-http-approval")
			if created.Code != 201 {
				t.Fatal("configuration apply", created.Code, created.Body.String())
			}
			replay := api("PUT", path, r, "schedule-http-approval")
			if replay.Code != 201 || replay.Header().Get("Idempotent-Replayed") != "true" || replay.Body.String() != created.Body.String() {
				t.Fatal("schedule replay changed original approval", replay.Code)
			}
			for _, url := range []string{path + "?unknown=x", path + "/history?limit=1&limit=2", path + "/runs?after=-1"} {
				if v := api("GET", url, nil, ""); v.Code != 400 {
					t.Fatal("unbounded/ambiguous schedule query", v.Code)
				}
			}
			workerToken, _ := crypt.Token()
			if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, "scheduled-worker", "worker", workerToken, time.Now().Add(time.Hour)); e != nil {
				t.Fatal(e)
			}
			identity, e := s.DB.AuthenticateWorker(ctx, workerToken)
			if e != nil {
				t.Fatal(e)
			}
			work, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			paused := false
			callbackError := ""
			options := worker.Options{Name: "scheduled-http", Identities: []store.WorkerIdentity{identity}, EventConcurrency: 1, IntegrityConcurrency: 1, MaintenanceConcurrency: 1, Lease: 3 * time.Second, Poll: 10 * time.Millisecond, Timeout: 5 * time.Second, MaxObjectBytes: 1 << 20, MaxEventBytes: 1 << 20}
			options.Notice = func(n worker.Notice) {
				if n.Queue != "maintenance" {
					return
				}
				if mode == "pause_pending" && n.State == "pending" && !paused {
					paused = true
					pause := r
					pause.ExpectedRevision = 1
					pause.Enabled = false
					pause.RunImmediately = false
					pause.AuthorizeFutureRetirements = false
					if v := api("PUT", path, pause, "pause-running-schedule"); v.Code != 200 {
						callbackError = "could not pause admitted schedule"
						cancel()
					}
				}
				if mode == "complete_restore" && n.State == "succeeded" || mode == "pause_pending" && n.State == "failed" {
					cancel()
				}
			}
			if e = worker.Run(work, s.DB, s.Blobs, options); e != nil {
				t.Fatal(e)
			}
			if callbackError != "" {
				t.Fatal(callbackError)
			}
			current, e := s.DB.RetentionSchedule(ctx, admin, "retained", "age")
			if e != nil || current.LastJob == "" {
				t.Fatal("real worker did not admit schedule", e)
			}
			detail, e := s.DB.RetentionRun(ctx, admin, current.LastJob)
			if e != nil {
				t.Fatal(e)
			}
			j := detail["job"].(store.Job)
			if mode == "pause_pending" {
				if !paused || j.State != "failed" || j.LastError != "retention_schedule_changed" || detail["processed"] != int64(1) || detail["retired"] != int64(1) {
					t.Fatal("pause did not leave an exact durable terminal outcome", j.State, j.LastError, detail["processed"])
				}
			} else {
				if j.State != "succeeded" || detail["retired"] != int64(2) || detail["plan"].(store.RetentionPlan).Schedule == nil {
					t.Fatal("scheduled run did not complete", j.State)
				}
				if v := api("GET", "/v2/retained/app/manifests/sha256:"+digests[0], nil, ""); v.Code != 404 {
					t.Fatal("automatic retirement left native reference live", v.Code)
				}
				restore := map[string]any{"path": "app/manifests/sha256:" + digests[0], "digest": digests[0], "expected_revision": 1, "action": "restore", "reason": "Verify exact automatically retired bytes"}
				if v := api("PUT", "/api/v1/repositories/retained/artifacts/lifecycle", restore, "restore-automatic-retirement"); v.Code != 200 {
					t.Fatal("verified restore", v.Code, v.Body.String())
				}
				if v := api("GET", "/v2/retained/app/manifests/sha256:"+digests[0], nil, ""); v.Code != 200 || crypt.Digest(v.Body.Bytes()) != digests[0] {
					t.Fatal("automatic retirement changed retained bytes", v.Code)
				}
				if v := api("GET", "/v2/retained/app/manifests/latest", nil, ""); v.Code != 200 || crypt.Digest(v.Body.Bytes()) != digests[2] {
					t.Fatal("restore rebound current tag", v.Code)
				}
			}
			for _, url := range []string{path, path + "/history?limit=1", path + "/runs?limit=1", policyPath + "/runs?limit=1"} {
				v := api("GET", url, nil, "")
				if v.Code != 200 || strings.Contains(v.Body.String(), token) || strings.Contains(v.Body.String(), admin.CredentialHash) || strings.Contains(v.Body.String(), workerToken) {
					t.Fatal("public scheduled-retention state/credential boundary", url, v.Code)
				}
			}
			for _, actor := range []struct {
				name, tenant, role string
				want               int
			}{{"reader", admin.Tenant, "reader", 403}, {"other", "schedule-other", "admin", 404}} {
				credential, _ := crypt.Token()
				if e = store.Provision(ctx, d.OwnerDSN, actor.tenant, actor.name, actor.role, credential, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				if v := lifecycleHTTP(t, s, credential)("GET", path, nil, ""); v.Code != actor.want {
					t.Fatal("schedule actor boundary", actor.role, v.Code)
				}
			}
			if v := lifecycleHTTP(t, s, workerToken)("GET", path, nil, ""); v.Code != 401 {
				t.Fatal("worker entered administrator API", v.Code)
			}
		})
	}
}
