// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// Same tenant fence as all mutations. Missing queue room preserves every pin.
func (s *Store) ExpireNextGoExportSet(ctx context.Context, i WorkerIdentity) (GoExportSetSession, error) {
	var out GoExportSetSession
	err := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		v, err := scanGoExportSet(tx.QueryRow(ctx, `SELECT `+goExportSetColumns+` FROM cratectl.artifact_export_sets WHERE state IN ('open','acknowledged') ORDER BY expires_at,id LIMIT 1`))
		if err != nil {
			return err
		}
		if v.State != "expired_unreconciled" {
			return ErrNotFound
		}
		if v.Generation == int64(^uint64(0)>>1) {
			return ErrGoExportSetChanged
		}
		who := Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}
		seq, err := nextEventSequence(ctx, tx, who)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE cratectl.artifact_export_sets SET state='expired',generation=generation+1,change_sequence=$1,changed_at=clock_timestamp() WHERE id=$2`, seq, v.ID); err != nil {
			return err
		}
		out, err = scanGoExportSet(tx.QueryRow(ctx, `SELECT `+goExportSetColumns+` FROM cratectl.artifact_export_sets WHERE id=$1`, v.ID))
		if err != nil {
			return err
		}
		return appendEventIntent(ctx, tx, who, "go.export-set.changed", out, true)
	})
	if err != nil {
		return GoExportSetSession{}, err
	}
	return out, nil
}
