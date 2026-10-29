// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"ctlplne.dev/cratectl/internal/store"
	"time"
)

// Stop renewing when attempt I/O expires, even if the underlying OS call stalls.
// A fenced completion can still record timeout while its current lease is live.
func keepJobLease(work context.Context, db *store.Store, i store.WorkerIdentity, j store.Job, lease time.Duration, cancelWork context.CancelFunc) (func(), func() error) {
	heart, stop := context.WithCancel(work)
	ended := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(ended)
		timer := time.NewTicker(lease / 3)
		defer timer.Stop()
		for {
			select {
			case <-heart.Done():
				return
			case <-timer.C:
				check, done := context.WithTimeout(heart, min(lease/3, 5*time.Second))
				e := db.RenewJob(check, i, j, lease)
				done()
				if e != nil && heart.Err() == nil {
					failures <- e
					cancelWork()
					return
				}
			}
		}
	}()
	return func() { stop(); <-ended }, func() error {
		select {
		case e := <-failures:
			return e
		default:
			return nil
		}
	}
}
