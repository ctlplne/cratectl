// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"math"
	"strings"
	"testing"
)

func TestRetentionScheduleRequiresExplicitBoundedFutureAuthority(t *testing.T) {
	good := RetentionScheduleRequest{RetentionScheduleSettings: RetentionScheduleSettings{IntervalSeconds: 60, MaxTargets: 100, Enabled: true, Reason: "Approve future bounded captures"}, ExpectedPolicyRevision: 1, AuthorizeFutureRetirements: true}
	if good.Validate() != nil {
		t.Fatal("valid explicit approval rejected")
	}
	for _, mutate := range []func(*RetentionScheduleRequest){
		func(r *RetentionScheduleRequest) { r.AuthorizeFutureRetirements = false }, func(r *RetentionScheduleRequest) { r.IntervalSeconds = 59 }, func(r *RetentionScheduleRequest) { r.IntervalSeconds = 31536001 }, func(r *RetentionScheduleRequest) { r.MaxTargets = 0 }, func(r *RetentionScheduleRequest) { r.MaxTargets = 10001 }, func(r *RetentionScheduleRequest) { r.ExpectedRevision = -1 }, func(r *RetentionScheduleRequest) { r.ExpectedRevision = math.MaxInt64 }, func(r *RetentionScheduleRequest) { r.ExpectedPolicyRevision = 0 }, func(r *RetentionScheduleRequest) { r.ExpectedSourceRevision = -1 }, func(r *RetentionScheduleRequest) { r.Reason = " " }, func(r *RetentionScheduleRequest) { r.Reason = "bad\nreason" }, func(r *RetentionScheduleRequest) { r.Reason = strings.Repeat("é", 513) }, func(r *RetentionScheduleRequest) { r.Enabled = false; r.RunImmediately = true },
	} {
		r := good
		mutate(&r)
		if r.Validate() == nil {
			t.Fatal("unsafe schedule accepted")
		}
	}
	good.Enabled = false
	good.AuthorizeFutureRetirements = false
	if good.Validate() != nil {
		t.Fatal("explicit pause rejected")
	}
}
