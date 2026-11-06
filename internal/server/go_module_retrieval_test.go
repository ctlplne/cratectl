// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestGoModuleFillFailureOnlyPermitsExplicitTransientStale(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"cancel", context.Canceled, "retrieval_cancelled"},
		{"deadline", context.DeadlineExceeded, "retrieval_cancelled"},
		{"destination", upstream.ErrDestination, "upstream_authority_failure"},
		{"redirect", upstream.ErrRedirect, "upstream_authority_failure"},
		{"path", upstream.ErrPath, "upstream_authority_failure"},
		{"checksum", errGoModuleChecksumRequired, "upstream_checksum_required"},
		{"configured-checksum", errGoModuleChecksumPublicationRequired, "upstream_checksum_required"},
		{"server", &goModuleOriginStatus{status: 503}, "transient_upstream_failure"},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "transient_upstream_failure"},
		{"reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, "transient_upstream_failure"},
		{"opaque-network", &net.OpError{Op: "remote error", Err: errors.New("owned opaque network failure")}, "upstream_go_module_validation_failure"},
		{"auth", &goModuleOriginStatus{status: 401}, "upstream_go_module_validation_failure"},
		{"throttle", &goModuleOriginStatus{status: 429}, "upstream_go_module_validation_failure"},
		{"partial", io.ErrUnexpectedEOF, "upstream_go_module_validation_failure"},
		{"invalid", store.ErrGoModuleUnvalidated, "upstream_go_module_validation_failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := goModuleFillFailure(fmt.Errorf("owned wrapper: %w", test.err)); got != test.want {
				t.Fatal("failure changed stale eligibility", got, test.want)
			}
		})
	}
}

func TestGoModuleOriginNegativeKeepsStrictestCacheHeaders(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		header http.Header
		fresh  int
	}{
		{"default", 404, http.Header{}, 30},
		{"gone", 410, http.Header{}, 30},
		{"short", 404, http.Header{"Cache-Control": {"max-age=9"}, "Age": {"2"}}, 7},
		{"no-cache-second", 404, http.Header{"Cache-Control": {"max-age=300", "no-cache"}}, 0},
		{"no-store-second", 404, http.Header{"Cache-Control": {"max-age=300", "no-store"}}, 0},
		{"vary-second", 404, http.Header{"Vary": {"Accept", "*"}}, 0},
		{"zero", 404, http.Header{"Cache-Control": {"max-age=0"}}, 0},
		{"invalid-age", 404, http.Header{"Cache-Control": {"max-age=300"}, "Age": {"broken"}}, 0},
		{"duplicate-age", 404, http.Header{"Age": {"1", "2"}}, 0},
		{"duplicate-expires", 404, http.Header{"Expires": {"Wed, 01 Jan 2031 00:00:00 GMT", "Wed, 01 Jan 2031 00:00:01 GMT"}}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _ := goOriginBytes(t)
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for k, values := range test.header {
					for _, v := range values {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(test.status)
			}))
			s, i, repo, lease := goOriginFixture(t, origin.URL, c)
			repo.Settings.Cache.NegativeSeconds = 30
			result, e := s.fetchGoModuleBundle(context.Background(), i, repo, lease)
			var status *goModuleOriginStatus
			if !errors.Is(e, errGoModuleOriginMissing) || !errors.As(e, &status) || status.status != test.status || status.fresh != test.fresh || calls.Load() != 1 || result.Object != nil || result.GoModule != nil {
				t.Fatal("negative lost bounded cache policy or fetched sibling", e, calls.Load())
			}
		})
	}
}
