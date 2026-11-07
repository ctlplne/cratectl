// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestGoChecksumProofPolicyRequiresExplicitReuseAndRejectsExpiryOrClockRollback(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		policy GoChecksumProofPolicy
		age    time.Duration
		want   error
	}{
		{"retained-old", GoChecksumProofPolicy{Mode: "retained"}, 100 * 365 * 24 * time.Hour, nil},
		{"recent", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}, 59 * time.Second, nil},
		{"exact-boundary", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}, 60 * time.Second, ErrGoChecksumProofExpired},
		{"expired", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}, 61 * time.Second, ErrGoChecksumProofExpired},
		{"clock-rollback", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}, -time.Microsecond, ErrGoChecksumProofExpired},
		{"largest-window", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: MaxGoChecksumProofAgeSeconds}, 24 * time.Hour, nil},
		{"missing", GoChecksumProofPolicy{}, 0, ErrGoModuleUnvalidated},
		{"unknown", GoChecksumProofPolicy{Mode: "automatic"}, 0, ErrGoModuleUnvalidated},
		{"implicit-retained-age", GoChecksumProofPolicy{Mode: "retained", MaxAgeSeconds: 60}, 0, ErrGoModuleUnvalidated},
		{"bounded-zero", GoChecksumProofPolicy{Mode: "max_age"}, 0, ErrGoModuleUnvalidated},
		{"bounded-negative", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: -1}, 0, ErrGoModuleUnvalidated},
		{"bounded-overflow", GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: MaxGoChecksumProofAgeSeconds + 1}, 0, ErrGoModuleUnvalidated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.check(now.Add(-tc.age), now); !errors.Is(err, tc.want) {
				t.Fatal("explicit proof reuse/age boundary", err, tc.want)
			}
		})
	}
	if err := (GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}).check(time.Time{}, now); !errors.Is(err, ErrGoChecksumProofExpired) {
		t.Fatal("missing observation time became recent proof", err)
	}
}

func FuzzGoChecksumProofPolicy(f *testing.F) {
	f.Add([]byte(`{"mode":"retained"}`))
	f.Add([]byte(`{"mode":"max_age","max_age_seconds":60}`))
	f.Add([]byte(`{"mode":"max_age","max_age_seconds":-1}`))
	f.Add([]byte(`{"mode":"max_age","max_age_seconds":999999999999999999999}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		var p GoChecksumProofPolicy
		if json.Unmarshal(raw, &p) != nil || p.validate() != nil {
			return
		}
		now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
		if p.Mode == "max_age" && (!errors.Is(p.check(now.Add(time.Second), now), ErrGoChecksumProofExpired) || !errors.Is(p.check(now.Add(-366*24*time.Hour), now), ErrGoChecksumProofExpired)) {
			t.Fatal("bounded policy admits future or year-old observation")
		}
		if err := p.check(now, now); err != nil {
			t.Fatal("explicit valid policy rejects just-accepted proof", err)
		}
	})
}
