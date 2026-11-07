// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/store"
)

// Reconcile at most one session per tenant visit. Busy execution lanes cannot
// starve expiry; replicas serialize with publication/renewal in PostgreSQL.
func runGoExportSetExpiry(ctx context.Context, db *store.Store, o Options, emit func(Notice)) {
	next := 0
	last := map[string]string{}
	for ctx.Err() == nil {
		i := o.Identities[next]
		next = (next + 1) % len(o.Identities)
		attempt, cancel := context.WithTimeout(ctx, min(o.Timeout, 30*time.Second))
		v, err := db.ExpireNextGoExportSet(attempt, i)
		cancel()
		if err == nil {
			delete(last, i.Tenant)
			emit(Notice{Tenant: i.Tenant, Queue: "maintenance", Generation: v.Generation, State: "go_export_set_expired"})
		} else if errors.Is(err, store.ErrNotFound) {
			delete(last, i.Tenant)
		} else if ctx.Err() == nil {
			code := "go_export_set_expiry_unavailable"
			if errors.Is(err, store.ErrUnauthenticated) {
				code = "go_export_set_expiry_worker_credential_unavailable"
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
