// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/store"
)

func executeRetention(parent context.Context, db *store.Store, o Options, i store.WorkerIdentity, j store.Job) string {
	ctx, cancel := context.WithTimeout(parent, min(o.Timeout, o.Lease))
	defer cancel()
	outcome, e := db.StepRetention(ctx, i, j)
	if e == nil {
		return outcome
	}
	if parent.Err() != nil {
		return "abandoned"
	}
	if errors.Is(e, store.ErrJobLeaseLost) || errors.Is(e, store.ErrUnauthenticated) {
		return "lease_or_credential_lost"
	}
	code := "handler_failure"
	permanent := false
	if errors.Is(e, store.ErrRetentionAuthorization) {
		code = "retention_requester_authorization"
		permanent = true
	}
	if errors.Is(e, store.ErrRetentionChanged) || errors.Is(e, store.ErrDenied) || errors.Is(e, store.ErrRepositorySuspended) || errors.Is(e, store.ErrRepositoryRemoved) {
		code = "retention_plan_changed"
		permanent = true
	}
	if errors.Is(e, store.ErrRetentionInput) {
		code = "invalid_target"
		permanent = true
	}
	complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer done()
	outcome, e = db.FailJob(complete, i, j, code, permanent)
	if e != nil {
		return "completion_unconfirmed"
	}
	return outcome
}
