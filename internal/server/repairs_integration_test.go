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
	"sync"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/testdb"
	"ctlplne.dev/cratectl/internal/upstream"
	"ctlplne.dev/cratectl/internal/worker"
	"github.com/jackc/pgx/v5"
)

func repairBytes(t *testing.T, s *Server, token, method, path, key string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func repairWorker(t *testing.T, s *Server, d testdb.Database) func() {
	t.Helper()
	ctx := context.Background()
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, d.OwnerDSN, "schema-http", "repair-worker", "worker", token, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	identity, e := s.DB.AuthenticateWorker(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	work, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- worker.Run(work, s.DB, s.Blobs, worker.Options{Name: "repair-test", Identities: []store.WorkerIdentity{identity}, EventConcurrency: 1, IntegrityConcurrency: 1, MaintenanceConcurrency: 1, Lease: 3 * time.Second, Poll: 10 * time.Millisecond, Timeout: 5 * time.Second, MaxObjectBytes: 1 << 20, MaxEventBytes: 1 << 20})
	}()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			stop()
			if e := <-done; e != nil {
				t.Error(e)
			}
		})
	}
	t.Cleanup(cleanup)
	return cleanup
}
func waitRepair(t *testing.T, s *Server, i store.Identity, id string, predicate func(store.Job) bool) store.Job {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	var last store.Job
	for time.Now().Before(deadline) {
		var e error
		last, e = s.DB.Job(context.Background(), i, id)
		if e != nil {
			t.Fatal(e)
		}
		if predicate(last) {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("repair did not reach expected state", last.State, last.LastError)
	return last
}
func repairPlanHTTP(t *testing.T, s *Server, token, repo, path, digest, key string) string {
	t.Helper()
	api := lifecycleHTTP(t, s, token)
	input := store.RepairRequest{Path: path, Digest: digest, Reason: "recover owned fixture", Provenance: "independent retained fixture source"}
	w := api("POST", "/api/v1/repositories/"+repo+"/artifacts/repairs", input, key)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		Job string `json:"job"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Job == "" {
		t.Fatal(w.Body.String())
	}
	return result.Job
}

func TestRepairHTTPRecoversCorruptSharedBytesWithoutChangingDenial(t *testing.T) {
	s, d, token, i := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	ctx := context.Background()
	data := []byte("retained source of exact bytes")
	digest := crypt.Digest(data)
	for _, repo := range []string{"repair-a", "repair-b"} {
		if w := api("POST", "/api/v1/repositories", map[string]string{"name": repo, "format": "generic"}, "create-"+repo); w.Code != 201 {
			t.Fatal(w.Body.String())
		}
		if w := repairBytes(t, s, token, "PUT", "/r/"+repo+"/file", "", data); w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	f, e := s.Blobs.Open(i.Tenant, digest)
	if e != nil {
		t.Fatal(e)
	}
	path := f.Name()
	f.Close()
	if e = os.WriteFile(path, bytes.Repeat([]byte("X"), len(data)), 0600); e != nil {
		t.Fatal(e)
	}
	if w := api("GET", "/r/repair-a/file", nil, ""); w.Code != 503 {
		t.Fatal("corrupt bytes served", w.Code)
	}
	input := store.RepairRequest{Path: "file", Digest: digest, Reason: "recover owned fixture", Provenance: "independent retained fixture source", DryRun: true}
	if w := api("POST", "/api/v1/repositories/repair-a/artifacts/repairs", input, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"affected_references":2`) {
		t.Fatal(w.Code, w.Body.String())
	}
	jobs, _, e := s.DB.Jobs(ctx, i, "integrity", "", "", 100)
	if e != nil {
		t.Fatal(e)
	}
	for _, j := range jobs {
		if j.Kind == "storage.repair" {
			t.Fatal("preview created repair intent")
		}
	}
	id := repairPlanHTTP(t, s, token, "repair-a", "file", digest, "repair-plan-a")
	stop := repairWorker(t, s, d)
	defer stop()
	job := waitRepair(t, s, i, id, func(j store.Job) bool { return j.State == "pending" })
	if job.Attempts != 0 || strings.Contains(string(job.Target), i.CredentialHash) || strings.Contains(string(job.Target), "requester") {
		t.Fatal("waiting source claimed or private fence exposed", job)
	}
	sourcePath := "/api/v1/maintenance/repairs/" + id + "/source"
	if w := repairBytes(t, s, token, "PUT", sourcePath, "repair-source-a", bytes.Repeat([]byte("Y"), len(data))); w.Code != 400 {
		t.Fatal("wrong bytes accepted", w.Code, w.Body.String())
	}
	if w := api("PUT", "/api/v1/repositories/repair-b/decisions", map[string]string{"path": "file", "digest": digest, "decision": "denied"}, "deny-shared-reference"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	accepted := repairBytes(t, s, token, "PUT", sourcePath, "repair-source-a", data)
	if accepted.Code != 202 {
		t.Fatal(accepted.Code, accepted.Body.String())
	}
	waitRepair(t, s, i, id, func(j store.Job) bool { return j.State == "succeeded" })
	if w := api("GET", "/r/repair-a/file", nil, ""); w.Code != 200 || w.Body.String() != string(data) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := api("GET", "/r/repair-b/file", nil, ""); w.Code != 403 {
		t.Fatal("repair changed denial", w.Code)
	}
	replay := repairBytes(t, s, token, "PUT", sourcePath, "repair-source-a", data)
	if replay.Code != 202 || replay.Header().Get("Idempotent-Replayed") != "true" || replay.Body.String() != accepted.Body.String() {
		t.Fatal("source replay changed response", replay.Code, replay.Body.String())
	}
	observations, _, e := s.DB.JobObservations(ctx, i, id, 0, 10)
	if e != nil || len(observations) != 1 || observations[0].Status != "verified" {
		t.Fatal("repair receipt missing", observations, e)
	}
	if w := api("GET", "/api/v1/jobs/"+id, nil, ""); w.Code != 200 || strings.Contains(w.Body.String(), i.CredentialHash) || strings.Contains(w.Body.String(), "requester") {
		t.Fatal("private job fence exposed", w.Body.String())
	}
}

func TestRepairInstallationSurvivesLostDatabaseReceiptAndReplaysReadback(t *testing.T) {
	s, d, token, i := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	ctx := context.Background()
	data := []byte("recover after installation commit fault")
	digest := crypt.Digest(data)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "repair-fault", "format": "generic"}, "create-fault"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if w := repairBytes(t, s, token, "PUT", "/r/repair-fault/file", "", data); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	f, e := s.Blobs.Open(i.Tenant, digest)
	if e != nil {
		t.Fatal(e)
	}
	path := f.Name()
	f.Close()
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	id := repairPlanHTTP(t, s, token, "repair-fault", "file", digest, "repair-fault-plan")
	if w := repairBytes(t, s, token, "PUT", "/api/v1/maintenance/repairs/"+id+"/source", "repair-fault-source", data); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `CREATE FUNCTION cratectl_private.repair_commit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.payload::jsonb->>'kind'='storage.repair.installed' THEN RAISE EXCEPTION 'owned repair receipt fault'; END IF; RETURN NEW;END $$;CREATE TRIGGER repair_commit_fault BEFORE INSERT ON cratectl.events FOR EACH ROW EXECUTE FUNCTION cratectl_private.repair_commit_fault()`); e != nil {
		t.Fatal(e)
	}
	stop := repairWorker(t, s, d)
	waitRepair(t, s, i, id, func(j store.Job) bool { return j.State == "retry" && j.LastError == "repair_attempt_unconfirmed" })
	stop()
	verified, e := s.Blobs.OpenVerified(ctx, i.Tenant, digest, int64(len(data)))
	if e != nil {
		t.Fatal("physical recovery did not occur", e)
	}
	verified.Close()
	observations, _, e := s.DB.JobObservations(ctx, i, id, 0, 10)
	if e != nil || len(observations) != 0 {
		t.Fatal("lost DB commit claimed completed verification", observations, e)
	}
	if _, e = owner.Exec(ctx, `DROP TRIGGER repair_commit_fault ON cratectl.events;DROP FUNCTION cratectl_private.repair_commit_fault()`); e != nil {
		t.Fatal(e)
	}
	stop = repairWorker(t, s, d)
	defer stop()
	waitRepair(t, s, i, id, func(j store.Job) bool { return j.State == "succeeded" })
	observations, _, e = s.DB.JobObservations(ctx, i, id, 0, 10)
	if e != nil || len(observations) != 1 || observations[0].Status != "verified" {
		t.Fatal(observations, e)
	}
}

func TestRepairRevokedRequesterAndCancellationFencePhysicalEffects(t *testing.T) {
	for _, action := range []string{"revoke", "cancel"} {
		t.Run(action, func(t *testing.T) {
			s, d, token, i := schemaServer(t)
			api := lifecycleHTTP(t, s, token)
			ctx := context.Background()
			data := []byte("never repair without live authority")
			digest := crypt.Digest(data)
			if w := api("POST", "/api/v1/repositories", map[string]string{"name": "repair-fenced", "format": "generic"}, "create-fenced"); w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			if w := repairBytes(t, s, token, "PUT", "/r/repair-fenced/file", "", data); w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			f, e := s.Blobs.Open(i.Tenant, digest)
			if e != nil {
				t.Fatal(e)
			}
			path := f.Name()
			f.Close()
			if e = os.Remove(path); e != nil {
				t.Fatal(e)
			}
			id := repairPlanHTTP(t, s, token, "repair-fenced", "file", digest, "repair-fenced-plan")
			if w := repairBytes(t, s, token, "PUT", "/api/v1/maintenance/repairs/"+id+"/source", "repair-fenced-source", data); w.Code != 202 {
				t.Fatal(w.Body.String())
			}
			if action == "cancel" {
				if _, e = s.DB.ControlJob(ctx, i, "repair-cancel", "repair-cancel-fp", id, "cancel", false); e != nil {
					t.Fatal(e)
				}
			} else {
				owner, e := pgx.Connect(ctx, d.OwnerDSN)
				if e != nil {
					t.Fatal(e)
				}
				_, e = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, i.CredentialHash)
				owner.Close(ctx)
				if e != nil {
					t.Fatal(e)
				}
			}
			stop := repairWorker(t, s, d)
			defer stop()
			if action == "revoke" {
				replacement, _ := crypt.Token()
				if e = store.Provision(ctx, d.OwnerDSN, "schema-http", "replacement", "admin", replacement, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				observer, e := s.DB.Authenticate(ctx, replacement)
				if e != nil {
					t.Fatal(e)
				}
				waitRepair(t, s, observer, id, func(j store.Job) bool { return j.State == "failed" && j.LastError == "repair_requester_authorization" })
			}
			if _, e = os.Stat(path); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("unauthorized repair installed bytes", e)
			}
		})
	}
}

func TestRepairRechecksPreparedEffectAgainstAuthoritySourceCancellationAndLease(t *testing.T) {
	for _, action := range []string{"revoke", "source-change", "cancel", "lease", "deadline"} {
		t.Run(action, func(t *testing.T) {
			s, d, token, i := schemaServer(t)
			ctx := context.Background()
			api := lifecycleHTTP(t, s, token)
			data := []byte("prepare outside transaction; fence every effect")
			digest := crypt.Digest(data)
			repository := store.Repository{Name: "repair-race", Format: "generic"}
			if action == "source-change" {
				repository.Mode = "proxy"
				repository.Settings = store.RepositorySettings{Upstream: &upstream.Config{URL: "https://original.invalid/", Networks: []string{"0.0.0.0/0"}}, Cache: store.CacheSettings{FreshSeconds: 60}}
			}
			if w := api("POST", "/api/v1/repositories", repository, "create-repair-race"); w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			if action == "source-change" {
				object, e := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), digest, int64(len(data)))
				if e != nil {
					t.Fatal(e)
				}
				lease, e := s.DB.AcquireRetrieval(ctx, i, "repair-race", "file", "initial-fill", true)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.DB.CompleteRetrieval(ctx, i, lease, store.RetrievalResult{Status: 200, Object: &object, FreshSeconds: 60}); e != nil {
					t.Fatal(e)
				}
			} else if w := repairBytes(t, s, token, "PUT", "/r/repair-race/file", "", data); w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			file, e := s.Blobs.Open(i.Tenant, digest)
			if e != nil {
				t.Fatal(e)
			}
			path := file.Name()
			file.Close()
			bad := bytes.Repeat([]byte("!"), len(data))
			if e = os.WriteFile(path, bad, 0600); e != nil {
				t.Fatal(e)
			}
			id := repairPlanHTTP(t, s, token, "repair-race", "file", digest, "repair-race-plan")
			if w := repairBytes(t, s, token, "PUT", "/api/v1/maintenance/repairs/"+id+"/source", "repair-race-source", data); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			credential, _ := crypt.Token()
			if e = store.Provision(ctx, d.OwnerDSN, i.Tenant, "manual-worker", "worker", credential, time.Now().Add(time.Hour)); e != nil {
				t.Fatal(e)
			}
			wi, e := s.DB.AuthenticateWorker(ctx, credential)
			if e != nil {
				t.Fatal(e)
			}
			var job store.Job
			for attempt := 0; attempt < 10; attempt++ {
				leaseBudget := time.Minute
				if action == "deadline" {
					leaseBudget = time.Second
				}
				job, e = s.DB.ClaimJob(ctx, wi, "integrity", "manual-repair", leaseBudget)
				if e != nil {
					t.Fatal(e)
				}
				if job.ID() == id {
					break
				}
				target, current, e := s.DB.JobIntegrityTarget(ctx, wi, job)
				if e != nil || !current {
					t.Fatal(target, current, e)
				}
				status, e := s.Blobs.CheckStored(ctx, i.Tenant, target.Digest, target.Size, 1<<20, 0)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = s.DB.FinishIntegrity(ctx, wi, job, status); e != nil {
					t.Fatal(e)
				}
			}
			if job.ID() != id {
				t.Fatal("repair was not claimed")
			}
			_, source, e := s.DB.JobRepair(ctx, wi, job)
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := s.Blobs.PrepareRepair(ctx, i.Tenant, source, 1<<20, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer prepared.Close()
			owner, e := pgx.Connect(ctx, d.OwnerDSN)
			if e != nil {
				t.Fatal(e)
			}
			defer owner.Close(ctx)
			want := store.ErrJobLeaseLost
			switch action {
			case "revoke":
				_, e = owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, i.CredentialHash)
				want = store.ErrRepairAuthorization
			case "source-change":
				next := store.RepositorySettings{Upstream: &upstream.Config{URL: "https://replacement.invalid/", Networks: []string{"0.0.0.0/0"}}}
				_, e = s.DB.ChangeConfiguration(ctx, i, "repair-race", "race-config-change", "race-config-fp", store.ConfigurationRequest{Settings: &next, Reason: "change after repair preparation"}, 10)
				want = store.ErrRepairChanged
			case "cancel":
				_, e = s.DB.ControlJob(ctx, i, "cancel-prepared-repair", "cancel-prepared-fp", id, "cancel", false)
				want = store.ErrJobCancelled
			case "lease":
				_, e = owner.Exec(ctx, `UPDATE cratectl.jobs SET generation=generation+1,lease_until='epoch' WHERE sequence=$1 AND task=$2`, job.Sequence, job.Task)
			case "deadline":
				want = context.DeadlineExceeded
			}
			if e != nil {
				t.Fatal(e)
			}
			called := false
			e = s.DB.ApplyRepair(ctx, wi, job, func(effect context.Context) (blob.RepairInstallation, error) {
				called = true
				if action == "deadline" {
					<-effect.Done()
				}
				return prepared.Install(effect)
			})
			if !errors.Is(e, want) || called != (action == "deadline") {
				t.Fatal("prepared effect ignored changed fence", action, called, e)
			}
			actual, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(actual, bad) {
				t.Fatal("fenced effect changed physical bytes", e)
			}
		})
	}
}

func TestRepairAdministrationIsTenantScopedAndPrivateFencesStayPrivate(t *testing.T) {
	s, d, token, i := schemaServer(t)
	api := lifecycleHTTP(t, s, token)
	ctx := context.Background()
	data := []byte("tenant scoped repair source")
	digest := crypt.Digest(data)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "repair-private", "format": "generic"}, "create-private-repair"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if w := repairBytes(t, s, token, "PUT", "/r/repair-private/file", "", data); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	id := repairPlanHTTP(t, s, token, "repair-private", "file", digest, "private-repair-plan")
	for _, role := range []string{"reader", "writer", "other"} {
		secret, _ := crypt.Token()
		tenant := i.Tenant
		provisionRole := role
		if role == "other" {
			tenant = "repair-other"
			provisionRole = "admin"
		}
		if e := store.Provision(ctx, d.OwnerDSN, tenant, role, provisionRole, secret, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		expected := 403
		if role == "other" {
			expected = 404
		}
		if w := repairBytes(t, s, secret, "PUT", "/api/v1/maintenance/repairs/"+id+"/source", "foreign-repair-source", data); w.Code != expected {
			t.Fatal("repair source crossed role/tenant", role, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/jobs/" + id, "/api/v1/jobs?limit=100"} {
		if w := api("GET", path, nil, ""); w.Code != 200 || strings.Contains(w.Body.String(), i.CredentialHash) || strings.Contains(w.Body.String(), "requester") {
			t.Fatal("private repair fence exposed", path, w.Code, w.Body.String())
		}
	}
}

func TestRepairIntentAndOutboxAdmissionFailTogether(t *testing.T) {
	s, d, token, i := schemaServer(t)
	ctx := context.Background()
	api := lifecycleHTTP(t, s, token)
	data := []byte("no repair without committed intent")
	digest := crypt.Digest(data)
	if w := api("POST", "/api/v1/repositories", map[string]string{"name": "repair-outbox", "format": "generic"}, "create-repair-outbox"); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if w := repairBytes(t, s, token, "PUT", "/r/repair-outbox/file", "", data); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `CREATE FUNCTION cratectl_private.repair_outbox_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.queue='events' AND NEW.kind='storage.repair.requested' THEN RAISE EXCEPTION 'owned repair outbox fault';END IF;RETURN NEW;END $$;CREATE TRIGGER repair_outbox_fault BEFORE INSERT ON cratectl.jobs FOR EACH ROW EXECUTE FUNCTION cratectl_private.repair_outbox_fault()`); e != nil {
		t.Fatal(e)
	}
	input := store.RepairRequest{Path: "file", Digest: digest, Reason: "test durable repair admission", Provenance: "independent retained test copy"}
	path := "/api/v1/repositories/repair-outbox/artifacts/repairs"
	if w := api("POST", path, input, "faulted-repair-admission"); w.Code != 503 {
		t.Fatal("outbox fault admitted repair", w.Code, w.Body.String())
	}
	jobs, _, e := s.DB.Jobs(ctx, i, "integrity", "", "", 100)
	if e != nil {
		t.Fatal(e)
	}
	for _, j := range jobs {
		if j.Kind == "storage.repair" {
			t.Fatal("uncommitted repair intent survived outbox failure")
		}
	}
	if _, e = owner.Exec(ctx, `DROP TRIGGER repair_outbox_fault ON cratectl.jobs;DROP FUNCTION cratectl_private.repair_outbox_fault()`); e != nil {
		t.Fatal(e)
	}
	if w := api("POST", path, input, "faulted-repair-admission"); w.Code != 202 || w.Header().Get("Idempotent-Replayed") == "true" {
		t.Fatal("failed admission committed a replay receipt", w.Code, w.Body.String())
	}
}
