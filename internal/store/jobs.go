// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrQueueFull = errors.New("durable queue capacity reached")
var ErrJobLeaseLost = errors.New("job lease expired or was superseded")
var ErrJobCancelled = errors.New("job cancellation requested")

type QueuePolicy struct {
	Queue           string `json:"queue"`
	Capacity        int    `json:"capacity"`
	MaxRunning      int    `json:"max_running"`
	MaxAttempts     int    `json:"max_attempts"`
	RetrySeconds    int    `json:"retry_seconds"`
	RetryMaxSeconds int    `json:"retry_max_seconds"`
}

func QueueName(name string) bool {
	return name == "events" || name == "integrity" || name == "maintenance"
}
func (p QueuePolicy) Validate() error {
	if !QueueName(p.Queue) || p.Capacity < 1 || p.Capacity > 2147483647 || p.MaxRunning < 1 || p.MaxRunning > 100000 || p.MaxAttempts < 1 || p.MaxAttempts > 10000 || p.RetrySeconds < 1 || p.RetryMaxSeconds < p.RetrySeconds || p.RetryMaxSeconds > 604800 {
		return ErrConflict
	}
	return nil
}
func queuePolicy(ctx context.Context, tx pgx.Tx, tenant, queue string) (QueuePolicy, error) {
	p := QueuePolicy{Queue: queue}
	if !QueueName(queue) {
		return p, ErrConflict
	}
	if _, e := tx.Exec(ctx, `INSERT INTO cratectl.queue_policies(tenant,queue) VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, queue); e != nil {
		return p, e
	}
	e := tx.QueryRow(ctx, `SELECT capacity,max_running,max_attempts,retry_seconds,retry_max_seconds FROM cratectl.queue_policies WHERE queue=$1`, queue).Scan(&p.Capacity, &p.MaxRunning, &p.MaxAttempts, &p.RetrySeconds, &p.RetryMaxSeconds)
	return p, e
}
func queueRoom(ctx context.Context, tx pgx.Tx, p QueuePolicy, count int) error {
	if count == 0 {
		return nil
	}
	if count < 0 {
		return ErrConflict
	}
	var n int64
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.jobs WHERE queue=$1 AND state NOT IN ('succeeded','failed','cancelled')`, p.Queue).Scan(&n); e != nil {
		return e
	}
	if int64(count) > int64(p.Capacity)-n {
		return ErrQueueFull
	}
	return nil
}
func enqueueEvent(ctx context.Context, tx pgx.Tx, i Identity, sequence int64, kind string) error {
	p, e := queuePolicy(ctx, tx, i.Tenant, "events")
	if e != nil {
		return e
	}
	if e = queueRoom(ctx, tx, p, 1); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,kind) VALUES($1,$2,$3)`, i.Tenant, sequence, kind)
	return e
}

type IntegrityTarget struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
}

func (t IntegrityTarget) Validate() error {
	_, e := hex.DecodeString(t.Digest)
	if !Name.MatchString(t.Repository) || len(t.Digest) != 64 || e != nil || t.Size < 0 || t.Size >= 1<<62 || t.Path == "" || len(t.Path) > 2048 {
		return ErrConflict
	}
	return nil
}
func enqueueIntegrity(ctx context.Context, tx pgx.Tx, i Identity, repo string, artifacts []Artifact) error {
	if len(artifacts) == 0 {
		return nil
	}
	if len(artifacts) > 4096 {
		return ErrMetadataLimit
	}
	sequence, e := nextEventSequence(ctx, tx, i)
	if e != nil {
		return e
	}
	targets := map[string]IntegrityTarget{}
	for _, a := range artifacts {
		target := IntegrityTarget{repo, a.Path, a.Digest, a.Size}
		if e = target.Validate(); e != nil {
			return e
		}
		key := "integrity-" + crypt.Digest([]byte(repo+"\x00"+a.Digest+"\x00"+strconv.FormatInt(a.Size, 10)))
		targets[key] = target
	}
	p, e := queuePolicy(ctx, tx, i.Tenant, "integrity")
	if e != nil {
		return e
	}
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	var present int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.jobs WHERE sequence=$1 AND task=ANY($2::text[])`, sequence, keys).Scan(&present); e != nil {
		return e
	}
	if e = queueRoom(ctx, tx, p, len(targets)-present); e != nil {
		return e
	}
	type row struct {
		Task    string          `json:"task"`
		Payload IntegrityTarget `json:"payload"`
	}
	rows := []row{}
	for key, target := range targets {
		rows = append(rows, row{key, target})
	}
	raw, _ := json.Marshal(rows)
	if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload) SELECT $1,$2,r.task,'integrity','artifact.integrity',r.payload FROM jsonb_to_recordset($3::jsonb) AS r(task text,payload jsonb) ON CONFLICT DO NOTHING`, i.Tenant, sequence, raw); e != nil {
		return e
	}

	return nil
}

type WorkerIdentity struct{ Tenant, Actor, CredentialHash string }

func (s *Store) AuthenticateWorker(ctx context.Context, token string) (WorkerIdentity, error) {
	var i WorkerIdentity
	if len(token) < 32 || len(token) > 256 {
		return i, ErrUnauthenticated
	}
	i.CredentialHash = crypt.Digest([]byte(token))
	tx, release, e := s.schemaTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if e != nil {
		return i, e
	}
	defer release()
	defer tx.Rollback(ctx)
	e = tx.QueryRow(ctx, `SELECT tenant,actor FROM cratectl.authenticate_worker($1)`, i.CredentialHash).Scan(&i.Tenant, &i.Actor)
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrUnauthenticated
	}
	if e == nil {
		e = tx.Commit(ctx)
	}
	return i, e
}
func (s *Store) workerTx(ctx context.Context, i WorkerIdentity, fn func(pgx.Tx) error) error {
	// A worker never uses owner/BYPASSRLS. Every operation reauthenticates the
	// dedicated credential, then uses the same tenant journal lock as mutations.
	if i.CredentialHash == "" {
		return ErrUnauthenticated
	}
	tx, release, e := s.schemaTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer release()
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT set_config('cratectl.tenant',$1,true),set_config('lock_timeout','5s',true),set_config('statement_timeout','30s',true)`, i.Tenant); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, i.Tenant); e != nil {
		return e
	}
	if e = checkWorkerIdentity(ctx, tx, i); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	if e = checkWorkerIdentity(ctx, tx, i); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func checkWorkerIdentity(ctx context.Context, tx pgx.Tx, i WorkerIdentity) error {
	var tenant, actor string
	e := tx.QueryRow(ctx, `SELECT tenant,actor FROM cratectl.authenticate_worker($1)`, i.CredentialHash).Scan(&tenant, &actor)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrUnauthenticated
	}
	if e != nil {
		return e
	}
	if tenant != i.Tenant || actor != i.Actor {
		return ErrUnauthenticated
	}
	return nil
}

type Job struct {
	Handler       string          `json:"handler"`
	Sequence      int64           `json:"sequence"`
	Task          string          `json:"task"`
	Queue         string          `json:"queue"`
	Kind          string          `json:"kind"`
	State         string          `json:"state"`
	Attempts      int             `json:"attempts"`
	CycleAttempts int             `json:"cycle_attempts"`
	Generation    int64           `json:"generation"`
	Worker        string          `json:"worker"`
	LeaseUntil    time.Time       `json:"lease_until"`
	AvailableAt   time.Time       `json:"available_at"`
	LastError     string          `json:"last_error"`
	UpdatedAt     time.Time       `json:"updated_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
	Target        json.RawMessage `json:"target"`
	Token         string          `json:"-"`
}

func (j Job) ID() string { return fmt.Sprintf("%d:%s", j.Sequence, j.Task) }
func ParseJobID(id string) (int64, string, error) {
	if len(id) > 96 {
		return 0, "", ErrConflict
	}
	seq, task, ok := strings.Cut(id, ":")
	n, e := strconv.ParseInt(seq, 10, 64)
	if !ok || e != nil || n < 1 || strconv.FormatInt(n, 10) != seq || strings.ToLower(task) != task {
		return 0, "", ErrConflict
	}
	if task != "event" {
		prefix, digest, found := strings.Cut(task, "-")
		if !found || (prefix != "integrity" && prefix != "reconcile" && prefix != "sweep" && prefix != "inventory" && prefix != "repair") || len(digest) != 64 {
			return 0, "", ErrConflict
		}
		if _, e = hex.DecodeString(digest); e != nil {
			return 0, "", ErrConflict
		}
	}
	return n, task, nil
}

const jobColumns = `sequence,task,queue,kind,state,attempts,cycle_attempts,generation,worker,lease_until,available_at,last_error,updated_at,finished_at,payload,lease_token`

func scanJob(row pgx.Row, j *Job) error {
	e := row.Scan(&j.Sequence, &j.Task, &j.Queue, &j.Kind, &j.State, &j.Attempts, &j.CycleAttempts, &j.Generation, &j.Worker, &j.LeaseUntil, &j.AvailableAt, &j.LastError, &j.UpdatedAt, &j.FinishedAt, &j.Target, &j.Token)
	if e == nil {
		j.Handler = "event.project"
		if j.Queue == "integrity" {
			j.Handler = "storage.integrity"
		}
		if j.Queue == "maintenance" {
			j.Handler = "leases.reconcile"
		}
		if j.Queue == "integrity" && j.Kind == "storage.inventory" {
			j.Handler = "storage.inventory"
		}
		if j.Queue == "integrity" && j.Kind == "storage.sweep" {
			j.Handler = "storage.sweep"
		}
		if j.Queue == "integrity" && j.Kind == "storage.repair" {
			j.Handler = "storage.repair"
			j.Target, e = publicRepairPayload(j.Target)
		}
	}
	return e
}
func jobAudit(ctx context.Context, tx pgx.Tx, i WorkerIdentity, kind string, j Job) error {
	return appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, kind, map[string]any{"job": j.ID(), "queue": j.Queue, "generation": j.Generation, "worker": j.Worker, "state": j.State}, false)
}
func (s *Store) ClaimJob(ctx context.Context, i WorkerIdentity, queue, worker string, lease time.Duration) (Job, error) {
	var j Job
	if !QueueName(queue) || !Name.MatchString(worker) || lease < time.Second || lease > 5*time.Minute {
		return j, ErrConflict
	}
	token, e := crypt.Token()
	if e != nil {
		return j, e
	}
	empty := false
	e = s.workerTx(ctx, i, func(tx pgx.Tx) error {
		p, e := queuePolicy(ctx, tx, i.Tenant, queue)
		if e != nil {
			return e
		}
		var active int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.jobs WHERE queue=$1 AND state IN ('running','cancel_requested') AND lease_until>clock_timestamp()`, queue).Scan(&active); e != nil {
			return e
		}
		if active >= p.MaxRunning {
			return ErrBusy
		}
		for skipped := 0; skipped < 32; skipped++ {
			e = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE queue=$1 AND (kind<>'storage.repair' OR payload->>'source_ready'='true') AND ((state IN ('pending','retry') AND available_at<=clock_timestamp()) OR (state IN ('running','cancel_requested') AND lease_until<=clock_timestamp())) ORDER BY available_at,sequence,task FOR UPDATE SKIP LOCKED LIMIT 1`, queue), &j)
			if errors.Is(e, pgx.ErrNoRows) {
				empty = true
				return nil
			}
			if e != nil {
				return e
			}
			if j.State == "cancel_requested" || j.CycleAttempts >= p.MaxAttempts {
				state, code := "failed", "attempts_exhausted"
				if j.State == "cancel_requested" {
					state, code = "cancelled", "cancelled"
				}
				if _, e = tx.Exec(ctx, `UPDATE cratectl.jobs SET state=$1,last_error=$2,lease_token='',lease_until='epoch',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE sequence=$3 AND task=$4`, state, code, j.Sequence, j.Task); e != nil {
					return e
				}
				j.State = state
				if e = jobAudit(ctx, tx, i, "job.recovered", j); e != nil {
					return e
				}
				continue
			}
			e = scanJob(tx.QueryRow(ctx, `UPDATE cratectl.jobs SET state='running',attempts=attempts+1,cycle_attempts=cycle_attempts+1,generation=generation+1,worker=$1,lease_token=$2,lease_until=clock_timestamp()+make_interval(secs=>$3),last_error='',updated_at=clock_timestamp(),finished_at=NULL WHERE sequence=$4 AND task=$5 RETURNING `+jobColumns, worker, token, lease.Seconds(), j.Sequence, j.Task), &j)
			if e != nil {
				return e
			}
			return jobAudit(ctx, tx, i, "job.claimed", j)
		}
		empty = true
		return nil
	})
	if e == nil && empty {
		e = ErrNotFound
	}
	return j, e
}
func leasedJob(ctx context.Context, tx pgx.Tx, j Job) (string, error) {
	var state string
	var live bool
	e := tx.QueryRow(ctx, `SELECT state,lease_until>clock_timestamp() FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND generation=$3 AND lease_token=$4 AND worker=$5 FOR UPDATE`, j.Sequence, j.Task, j.Generation, j.Token, j.Worker).Scan(&state, &live)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", ErrJobLeaseLost
	}
	if e != nil {
		return "", e
	}
	if !live || state != "running" && state != "cancel_requested" {
		return "", ErrJobLeaseLost
	}
	return state, nil
}
func (s *Store) RenewJob(ctx context.Context, i WorkerIdentity, j Job, lease time.Duration) error {
	if lease < time.Second || lease > 5*time.Minute {
		return ErrConflict
	}
	return s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		_, e = tx.Exec(ctx, `UPDATE cratectl.jobs SET lease_until=clock_timestamp()+make_interval(secs=>$1),updated_at=clock_timestamp() WHERE sequence=$2 AND task=$3`, lease.Seconds(), j.Sequence, j.Task)
		return e
	})
}
