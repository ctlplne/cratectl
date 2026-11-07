// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"testing"
)

func TestGoExportPlanningInputsRefuseBeforeDatabaseAdmission(t *testing.T) {
	request := GoExportSetRequest{Entries: []GoExportSetEntry{{Repository: "owned", Module: "example.invalid/a", Version: "v1.0.0"}}, LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20}
	identity := Identity{Tenant: "owned", Actor: "operator", Role: "admin"}
	var unavailable *Store
	for _, reads := range [][]GoExportPlan{nil, make([]GoExportPlan, MaxGoExportPlanningInputs+1), {{}}, {{tenant: "other", actor: identity.Actor}}} {
		got, err := unavailable.PlanGoExportSetAfterReads(context.Background(), identity, request, reads)
		if !errors.Is(err, ErrGoExportSetInput) || len(got.Bytes()) != 0 {
			t.Fatal("invalid resolution input reached the database or exposed metadata", err)
		}
	}
}
