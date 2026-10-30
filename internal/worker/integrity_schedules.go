// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/store"
)

// One independent bounded loop prevents busy execution lanes from starving due
// admissions. Replicas serialize each tenant's admission in PostgreSQL.
func runIntegritySchedules(ctx context.Context, db *store.Store, o Options, emit func(Notice)) {
	next := 0
	last := map[string]string{}
	for ctx.Err() == nil {
		i := o.Identities[next]
		next = (next + 1) % len(o.Identities)
		attempt, cancel := context.WithTimeout(ctx, min(o.Timeout, 30*time.Second))
		out, e := db.DispatchIntegritySchedule(attempt, i)
		cancel()
		if e == nil {
			if out.State == "admitted" || last[i.Tenant] != out.State {
				emit(Notice{Tenant: i.Tenant, Queue: "maintenance", Job: out.Job, State: "schedule_" + out.State})
			}
			last[i.Tenant] = out.State
		} else if !errors.Is(e, store.ErrNotFound) && ctx.Err() == nil {
			code := "schedule_admission_unavailable"
			if errors.Is(e, store.ErrUnauthenticated) {
				code = "schedule_worker_credential_unavailable"
			} else if errors.Is(e, store.ErrScheduleAuthorization) {
				code = "schedule_requester_authorization_changed"
			}
			if last[i.Tenant] != code {
				emit(Notice{Tenant: i.Tenant, Queue: "maintenance", State: code})
			}
			last[i.Tenant] = code
		}
		timer := time.NewTimer(max(o.Poll, time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
