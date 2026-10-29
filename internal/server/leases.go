// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"sync"
	"time"
)

// keepLease cancels I/O if renewal fails. Stop waits for a pending renewal and
// must be called before accepting an effect; acceptance rechecks the SQL fence.
func keepLease(parent context.Context, lease time.Duration, renew func(context.Context) error, abort func()) (context.Context, func() error, context.CancelFunc) {
	work, cancel := context.WithCancel(parent)
	heart, stop := context.WithCancel(work)
	ended := make(chan error, 1)
	go func() {
		timer := time.NewTicker(lease / 3)
		defer timer.Stop()
		for {
			select {
			case <-heart.Done():
				ended <- nil
				return
			case <-timer.C:
				check, done := context.WithTimeout(heart, min(lease/3, 5*time.Second))
				e := renew(check)
				done()
				if e != nil && heart.Err() == nil {
					cancel()
					if abort != nil {
						abort()
					}
					ended <- e
					return
				}
			}
		}
	}()
	var once sync.Once
	var result error
	finish := func() error { once.Do(func() { stop(); result = <-ended }); return result }
	return work, finish, func() { cancel(); finish() }
}
