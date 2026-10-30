//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/worker"
	"github.com/jackc/pgx/v5"
)

func TestIntegrityScheduleHTTPWorkerReadsActualBytesAndSurvivesRestart(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	ctx := context.Background()
	api := lifecycleHTTP(t, s, token)
	root := t.TempDir()
	objects, e := blob.New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	s.Blobs = objects
	if w := api("POST", "/api/v1/repositories", map[string]any{"name": "packages", "format": "generic"}, "schedule-repo"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	data := []byte("owned recurring bytes\n")
	digest := crypt.Digest(data)
	for path, body := range map[string][]byte{"first": data, "second": []byte("independent healthy object\n")} {
		w := repairBytes(t, s, token, "PUT", "/r/packages/"+path, "", body)
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if e = os.WriteFile(filepath.Join(root, admin.Tenant, "sha256", digest[:2], digest), []byte(strings.Repeat("X", len(data))), 0600); e != nil {
		t.Fatal(e)
	}
	if w := api("PUT", "/api/v1/repositories/packages/decisions", map[string]any{"path": "first", "digest": digest, "decision": "denied"}, "schedule-denial"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "/api/v1/maintenance/integrity-schedules/recurring"
	input := store.ScheduleRequest{ScheduleSettings: store.ScheduleSettings{Repository: "packages", IntervalSeconds: 60, SampleSize: 100, Enabled: true, Reason: "Observe actual owned corruption without approving it"}, RunImmediately: true}
	preview := input
	preview.DryRun = true
	if w := api("PUT", path, preview, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", path, nil, ""); w.Code != 404 {
		t.Fatal("preview created configuration", w.Code)
	}
	created := api("PUT", path, input, "recurring-create")
	if created.Code != 201 {
		t.Fatal(created.Code, created.Body.String())
	}
	replayed := api("PUT", path, input, "recurring-create")
	if replayed.Code != 201 || replayed.Header().Get("Idempotent-Replayed") != "true" || replayed.Body.String() != created.Body.String() {
		t.Fatal("configuration replay changed", replayed.Code, replayed.Body.String())
	}
	if w := api("PUT", path, input, "stale-revision"); w.Code != 409 || !strings.Contains(w.Body.String(), "schedule_changed") {
		t.Fatal("stale configuration accepted", w.Code, w.Body.String())
	}
	workerToken, _ := crypt.Token()
	if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, "schedule-worker", "worker", workerToken, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	identity, e := s.DB.AuthenticateWorker(ctx, workerToken)
	if e != nil {
		t.Fatal(e)
	}
	start := func() func() {
		work, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			done <- worker.Run(work, s.DB, s.Blobs, worker.Options{Name: "schedule-test", Identities: []store.WorkerIdentity{identity}, EventConcurrency: 1, IntegrityConcurrency: 1, MaintenanceConcurrency: 1, Lease: 3 * time.Second, Poll: 10 * time.Millisecond, Timeout: 5 * time.Second, MaxObjectBytes: 1 << 20, MaxEventBytes: 1 << 20})
		}()
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				cancel()
				if e := <-done; e != nil {
					t.Error(e)
				}
			}
		}
		t.Cleanup(stop)
		return stop
	}
	await := func(count int) []store.ScheduleRun {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			rows, _, e := s.DB.IntegrityScheduleRuns(ctx, admin, "recurring", 0, 100)
			if e != nil {
				t.Fatal(e)
			}
			if len(rows) == count && rows[count-1].State == "succeeded" {
				return rows
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("automatic schedule did not complete")
		return nil
	}
	stop := start()
	first := await(1)
	if !first[0].SampleAssessed || first[0].SampleClean || first[0].Progress.Issues != 1 || first[0].Progress.Verified != 1 || first[0].AllTenantContentAssessed || first[0].SecurityApproval {
		t.Fatal("dishonest physical readback", first)
	}
	stop()
	if w := api("GET", "/r/packages/first", nil, ""); w.Code != 403 {
		t.Fatal("integrity observation changed denial", w.Code)
	}
	input.ExpectedRevision = 1
	input.Enabled = false
	input.RunImmediately = false
	if w := api("PUT", path, input, "pause-recurring"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `UPDATE cratectl.integrity_schedules SET next_due_at='epoch',retry_at='epoch' WHERE tenant=$1 AND name='recurring'`, admin.Tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.DispatchIntegritySchedule(ctx, identity); e != store.ErrNotFound {
		t.Fatal("paused configuration admitted", e)
	}
	input.ExpectedRevision = 2
	input.Enabled = true
	input.RunImmediately = true
	if w := api("PUT", path, input, "resume-recurring"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	stop = start()
	rows := await(2)
	stop()
	if rows[0].Job != first[0].Job || rows[1].Job == first[0].Job || rows[1].Revision != 3 || rows[1].Progress.Issues != 1 {
		t.Fatal("restart lost or rewrote run history", rows)
	}
	for _, suffix := range []string{"", "/history?limit=1", "/runs?limit=1"} {
		w := api("GET", path+suffix, nil, "")
		if w.Code != 200 || strings.Contains(w.Body.String(), admin.CredentialHash) || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), workerToken) {
			t.Fatal("private fence exposed", w.Code)
		}
	}
	bad := []string{path + "?unexpected=1", path + "/runs?limit=1&limit=2", path + "/history?after=-1", "/api/v1/maintenance/integrity-schedules?after=BAD", "/api/v1/maintenance/integrity-schedules?limit=%zz"}
	for _, p := range bad {
		if w := api("GET", p, nil, ""); w.Code != 400 {
			t.Fatal("unbounded/ambiguous query accepted", p, w.Code)
		}
	}
}

func TestIntegrityScheduleHTTPPurposeAndTenantBoundaries(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	path := "/api/v1/maintenance/integrity-schedules/scoped"
	input := store.ScheduleRequest{ScheduleSettings: store.ScheduleSettings{IntervalSeconds: 60, SampleSize: 1, Enabled: false, Reason: "Owned purpose boundary"}}
	if w := api("PUT", path, input, "scoped-schedule"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, spec := range []struct {
		tenant, role string
		status       int
	}{{admin.Tenant, "reader", 403}, {admin.Tenant, "writer", 403}, {"schedule-other", "admin", 404}} {
		token, _ := crypt.Token()
		if e := store.Provision(context.Background(), d.OwnerDSN, spec.tenant, "boundary", spec.role, token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		other := lifecycleHTTP(t, s, token)
		if w := other("GET", path, nil, ""); w.Code != spec.status {
			t.Fatal("schedule boundary", spec, w.Code)
		}
		if spec.role != "admin" {
			if w := other("PUT", path, input, "forbidden-config"); w.Code != 403 {
				t.Fatal("nonadmin changed schedule", w.Code)
			}
		}
	}
	for _, body := range []string{`{}`, strings.Replace(scheduleJSON, `"enabled":true`, `"enabled":true,"enabled":false`, 1)} {
		r := httptest.NewRequest("PUT", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", "invalid-plan-key")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("ambiguous body accepted", w.Code)
		}
	}
	var result store.IntegritySchedule
	w := api("GET", path, nil, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Revision != 1 {
		t.Fatal("invalid requests changed configuration", w.Code, w.Body.String())
	}
}
