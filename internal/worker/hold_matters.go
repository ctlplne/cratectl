// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/store"
)

func executeHoldMatter(parent context.Context, db *store.Store, o Options, i store.WorkerIdentity, j store.Job) string {
	ctx, cancel := context.WithTimeout(parent, min(o.Timeout, o.Lease))
	defer cancel()
	outcome, e := db.StepHoldMatter(ctx, i, j)
	if e == nil {
		return outcome
	}
	if parent.Err() != nil {
		return "abandoned"
	}
	if errors.Is(e, store.ErrJobLeaseLost) || errors.Is(e, store.ErrUnauthenticated) {
		return "lease_or_credential_lost"
	}
	code, permanent := "handler_failure", false
	switch {
	case errors.Is(e, store.ErrMatterAuthorization):
		code, permanent = "hold_matter_authorization", true
	case errors.Is(e, store.ErrMatterChanged), errors.Is(e, store.ErrDenied), errors.Is(e, store.ErrNotFound):
		code, permanent = "hold_matter_changed", true
	case errors.Is(e, store.ErrMatterInput), errors.Is(e, store.ErrConflict):
		code, permanent = "invalid_target", true
	}
	complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer done()
	outcome, e = db.FailJob(complete, i, j, code, permanent)
	if e != nil {
		return "completion_unconfirmed"
	}
	return outcome
}
