// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"errors"
	"sync"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/store"
)

type Notice struct {
	Tenant     string `json:"tenant"`
	Queue      string `json:"queue"`
	Job        string `json:"job,omitempty"`
	Generation int64  `json:"generation,omitempty"`
	State      string `json:"state"`
}
type Options struct {
	Name                                          string
	Identities                                    []store.WorkerIdentity
	EventConcurrency, IntegrityConcurrency        int
	MaintenanceConcurrency                        int
	Lease, Poll, Timeout                          time.Duration
	MaxObjectBytes, MaxEventBytes, BytesPerSecond int64
	Notice                                        func(Notice)
}

func (o Options) Validate() error {
	if o.MaintenanceConcurrency < 1 || o.MaintenanceConcurrency > 256 {
		return store.ErrConflict
	}
	if !store.Name.MatchString(o.Name) || len(o.Identities) == 0 || o.EventConcurrency < 1 || o.EventConcurrency > 256 || o.IntegrityConcurrency < 1 || o.IntegrityConcurrency > 256 || o.Lease < time.Second || o.Lease > 5*time.Minute || o.Poll < 10*time.Millisecond || o.Poll > time.Minute || o.Timeout < time.Second || o.Timeout > 24*time.Hour || o.MaxObjectBytes < 1 || o.MaxObjectBytes >= 1<<62 || o.MaxEventBytes < 1 || o.MaxEventBytes > 1<<30 || o.BytesPerSecond < 0 {
		return store.ErrConflict
	}
	seen := map[string]bool{}
	for _, i := range o.Identities {
		if !store.Name.MatchString(i.Tenant) || !store.Name.MatchString(i.Actor) || i.CredentialHash == "" || seen[i.Tenant] {
			return store.ErrConflict
		}
		seen[i.Tenant] = true
	}
	return nil
}

type lane struct {
	mu     sync.Mutex
	next   int
	errors map[string]string
}

func Run(ctx context.Context, db *store.Store, objects *blob.Local, o Options) error {
	if e := o.Validate(); e != nil {
		return e
	}
	var notices sync.Mutex
	emit := func(n Notice) {
		if o.Notice != nil {
			notices.Lock()
			o.Notice(n)
			notices.Unlock()
		}
	}
	var all sync.WaitGroup
	all.Add(1)
	go func() { defer all.Done(); runIntegritySchedules(ctx, db, o, emit) }()
	for queue, count := range map[string]int{"events": o.EventConcurrency, "integrity": o.IntegrityConcurrency, "maintenance": o.MaintenanceConcurrency} {
		lane := &lane{errors: map[string]string{}}
		for n := 0; n < count; n++ {
			all.Add(1)
			go func(queue string) {
				defer all.Done()
				for ctx.Err() == nil {
					claimed := false
					for attempt := 0; attempt < len(o.Identities) && ctx.Err() == nil; attempt++ {
						lane.mu.Lock()
						i := o.Identities[lane.next]
						lane.next = (lane.next + 1) % len(o.Identities)
						lane.mu.Unlock()
						job, e := db.ClaimJob(ctx, i, queue, o.Name, o.Lease)
						if e != nil {
							if !errors.Is(e, store.ErrNotFound) && !errors.Is(e, store.ErrBusy) && ctx.Err() == nil {
								code := "queue_unavailable"
								if errors.Is(e, store.ErrUnauthenticated) {
									code = "worker_credential_unavailable"
								}
								lane.mu.Lock()
								changed := lane.errors[i.Tenant] != code
								lane.errors[i.Tenant] = code
								lane.mu.Unlock()
								if changed {
									emit(Notice{Tenant: i.Tenant, Queue: queue, State: code})
								}
							}
							continue
						}
						lane.mu.Lock()
						delete(lane.errors, i.Tenant)
						lane.mu.Unlock()
						claimed = true
						emit(Notice{i.Tenant, queue, job.ID(), job.Generation, "running"})
						state := execute(ctx, db, objects, o, i, job)
						emit(Notice{i.Tenant, queue, job.ID(), job.Generation, state})
						break
					}
					if !claimed {
						timer := time.NewTimer(o.Poll)
						select {
						case <-ctx.Done():
							timer.Stop()
						case <-timer.C:
						}
					}
				}
			}(queue)
		}
	}
	all.Wait()
	return nil
}
func execute(parent context.Context, db *store.Store, objects *blob.Local, o Options, i store.WorkerIdentity, j store.Job) string {
	if j.Kind == "repository.retention" {
		return executeRetention(parent, db, o, i, j)
	}
	if j.Kind == "storage.repair" {
		return executeRepair(parent, db, objects, o, i, j)
	}
	if j.Kind == "storage.inventory" {
		return executeInventory(parent, db, objects, o, i, j)
	}
	if j.Queue == "maintenance" {
		ctx, cancel := context.WithTimeout(parent, min(o.Timeout, o.Lease))
		defer cancel()
		outcome, e := db.ReconcileLeases(ctx, i, j)
		if e == nil {
			return outcome
		}
		if parent.Err() != nil {
			return "abandoned"
		}
		if errors.Is(e, store.ErrJobLeaseLost) || errors.Is(e, store.ErrUnauthenticated) {
			return "lease_or_credential_lost"
		}
		complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer done()
		outcome, e = db.FailJob(complete, i, j, "handler_failure", errors.Is(e, store.ErrConflict))
		if e != nil {
			return "completion_unconfirmed"
		}
		return outcome
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	stopHeart, heartError := keepJobLease(ctx, db, i, j, o.Lease, cancel)
	defer stopHeart()
	var projection store.EventProjection
	var status string
	var e error
	var sweepItem store.SweepItem
	if j.Queue == "events" {
		projection, e = db.JobEvent(ctx, i, j, o.MaxEventBytes)
	} else if j.Kind == "storage.sweep" {
		var empty bool
		sweepItem, empty, e = db.NextSweepItem(ctx, i, j)
		if e == nil && !empty {
			status, e = objects.CheckStored(ctx, i.Tenant, sweepItem.Digest, sweepItem.Size, o.MaxObjectBytes, o.BytesPerSecond)
		}
	} else {
		var target store.IntegrityTarget
		var current bool
		target, current, e = db.JobIntegrityTarget(ctx, i, j)
		if e == nil {
			if !current {
				status = "superseded"
			} else {
				status, e = objects.CheckStored(ctx, i.Tenant, target.Digest, target.Size, o.MaxObjectBytes, o.BytesPerSecond)
			}
		}
	}
	if parent.Err() != nil {
		return "abandoned"
	}
	heartbeat := heartError()
	if heartbeat != nil && !errors.Is(heartbeat, store.ErrJobCancelled) {
		return "lease_or_credential_lost"
	}
	complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer done()
	var outcome string
	switch {
	case errors.Is(heartbeat, store.ErrJobCancelled) || errors.Is(e, store.ErrJobCancelled):
		outcome, e = db.FailJob(complete, i, j, "worker_stopped", false)
	case j.Queue == "events" && e == nil:
		outcome, e = db.FinishEvent(complete, i, j, projection)
	case j.Kind == "storage.sweep" && (e == nil || errors.Is(e, context.DeadlineExceeded)):
		if sweepItem.Ordinal > 0 && status == "" {
			status = "timeout"
		}
		outcome, e = db.FinishSweepItem(complete, i, j, sweepItem, status)
	case j.Queue == "integrity" && (e == nil || errors.Is(e, context.DeadlineExceeded)):
		if status == "" {
			status = "timeout"
		}
		outcome, e = db.FinishIntegrity(complete, i, j, status)
	default:
		code, permanent := "handler_failure", false
		if errors.Is(e, store.ErrMetadataLimit) {
			code, permanent = "event_budget", true
		} else if errors.Is(e, store.ErrConflict) || errors.Is(e, store.ErrScheduleEvidence) {
			code, permanent = "invalid_event", true
			if j.Queue == "integrity" {
				code = "invalid_target"
			}
		} else if errors.Is(e, context.DeadlineExceeded) {
			code = "handler_timeout"
		}
		outcome, e = db.FailJob(complete, i, j, code, permanent)
	}
	if e != nil {
		return "completion_unconfirmed"
	}
	return outcome
}
