// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"errors"
	"time"
)

var ErrGoChecksumProofExpired = errors.New("Go checksum proof requires current verification under configured age policy")

// Retained explicitly imposes no proof age requirement. Max-age measures time
// since cratectl accepted a complete independently verified proof, not the age
// of the external log's contents. Neither mode overrides package cache, policy,
// lifecycle, source or current exact-key trust, or grants disconnected installs.
type GoChecksumProofPolicy struct {
	Mode          string `json:"mode"`
	MaxAgeSeconds int    `json:"max_age_seconds,omitempty"`
}

const MaxGoChecksumProofAgeSeconds = 365 * 24 * 60 * 60

func (p GoChecksumProofPolicy) validate() error {
	if p.Mode == "retained" && p.MaxAgeSeconds == 0 || p.Mode == "max_age" && p.MaxAgeSeconds > 0 && p.MaxAgeSeconds <= MaxGoChecksumProofAgeSeconds {
		return nil
	}
	return ErrGoModuleUnvalidated
}

func (p GoChecksumProofPolicy) check(accepted, now time.Time) error {
	if err := p.validate(); err != nil {
		return err
	}
	if p.Mode == "retained" {
		return nil
	}
	// PostgreSQL supplies both times. Reject an observation from the future
	// and the exact expiry boundary rather than extending trust after rollback.
	if accepted.IsZero() || now.Before(accepted) || !now.Before(accepted.Add(time.Duration(p.MaxAgeSeconds)*time.Second)) {
		return ErrGoChecksumProofExpired
	}
	return nil
}
