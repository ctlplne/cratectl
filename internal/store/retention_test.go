// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"strings"
	"testing"
)

func TestRetentionSettingsRejectUnsafeOrUnboundedRules(t *testing.T) {
	good := RetentionSettings{MinAgeSeconds: 60, KeepLast: 0, ProtectTagged: true, Enabled: true, Reason: "Retain the newest live versions"}
	if e := good.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, r := range []RetentionSettings{
		{MinAgeSeconds: 0, Reason: good.Reason},
		{MinAgeSeconds: 315360001, Reason: good.Reason},
		{MinAgeSeconds: 60, KeepLast: -1, Reason: good.Reason},
		{MinAgeSeconds: 60, KeepLast: 1000001, Reason: good.Reason},
		{MinAgeSeconds: 60, Reason: " "},
		{MinAgeSeconds: 60, Reason: "unbounded\nreason"},
		{MinAgeSeconds: 60, Reason: strings.Repeat("x", 1025)},
		{MinAgeSeconds: 60, Reason: string([]byte{0xff})},
	} {
		if r.Validate() == nil {
			t.Fatal("unsafe rule accepted", r)
		}
	}
}
