// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

const MaxGoExportPlanningInputs = 1024
const maxGoExportPlanningMetadata = 32 << 20

// PlanGoExportSetAfterReads revalidates all caller-examined source manifests,
// including versions that influenced dependency selection but were not selected.
// The caller performs bounded CAS reads before this method, outside a database
// transaction. Every input and final selected root is checked in one current
// tenant-scoped repeatable-read/read-only snapshot. No input is pinned and no
// mutation, session, receipt, job or closure/admission grant is created.
//
// This unsigned preview is not a commit fence or durable graph proof. Creation
// must repeat every resolution-input guard under its mutation fence, and package
// and platform closure still require independent verification.
func (s *Store) PlanGoExportSetAfterReads(ctx context.Context, i Identity, r GoExportSetRequest, reads []GoExportPlan) (GoExportSetPlan, error) {
	if r.Validate() != nil || len(reads) < 1 || len(reads) > MaxGoExportPlanningInputs {
		return GoExportSetPlan{}, ErrGoExportSetInput
	}
	if i.Role != "admin" {
		return GoExportSetPlan{}, ErrDenied
	}
	r.Entries = append([]GoExportSetEntry(nil), r.Entries...)
	reads = append([]GoExportPlan(nil), reads...)
	seen := make(map[gomodule.Coordinate]bool, len(reads))
	metadata := 0
	for _, input := range reads {
		coordinate := input.Coordinate()
		if input.tenant != i.Tenant || input.actor != i.Actor || input.request.Validate() != nil || seen[coordinate] ||
			len(input.raw) < 1 || len(input.raw) > MaxGoExportManifest || len(input.raw) > maxGoExportPlanningMetadata-metadata {
			return GoExportSetPlan{}, ErrGoExportSetInput
		}
		canonical, err := input.manifest.Bytes()
		if err != nil || !bytes.Equal(canonical, input.raw) {
			return GoExportSetPlan{}, ErrGoExportSetInput
		}
		seen[coordinate] = true
		metadata += len(input.raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out GoExportSetPlan
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		for _, input := range reads {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Preserve the original observation fields solely for an exact source
			// comparison. The final set gets this transaction's common clock/head.
			current, err := goExportManifestInTx(ctx, tx, i, input.request, input.manifest.PreparedAt, input.manifest.ObservedJournal)
			if errors.Is(err, ErrSourceChanged) {
				return ErrGoExportSetChanged
			}
			if err != nil {
				return err
			}
			raw, err := current.Bytes()
			if err != nil || !bytes.Equal(raw, input.raw) {
				return ErrGoExportSetChanged
			}
		}
		var err error
		out, err = planGoExportSetInTx(ctx, tx, i, r)
		return err
	})
	if err != nil {
		return GoExportSetPlan{}, err
	}
	return out, nil
}
