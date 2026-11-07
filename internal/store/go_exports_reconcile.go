// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ExpireNextGoExport releases one due session's payload roots. It cannot renew,
// acknowledge, download, or grant artifact access. Dedicated worker credentials
// are rechecked under the tenant mutation fence and again before commit.
// The terminal state and its journal/projection intent commit together; a lost
// response or another worker cannot expire the same generation a second time.
func (s *Store) ExpireNextGoExport(ctx context.Context, i WorkerIdentity) (GoExportSession, error) {
	var out GoExportSession
	err := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		v, err := scanGoExport(tx.QueryRow(ctx, `SELECT `+goExportColumns+` FROM cratectl.artifact_exports WHERE state IN ('open','acknowledged') AND expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT 1`))
		if err != nil {
			return err
		}
		if v.State != "expired_unreconciled" || v.Generation == int64(^uint64(0)>>1) {
			return ErrGoExportChanged
		}
		identity := Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}
		seq, err := nextEventSequence(ctx, tx, identity)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET state='expired',generation=generation+1,change_sequence=$1,changed_at=clock_timestamp() WHERE id=$2`, seq, v.ID); err != nil {
			return err
		}
		out, err = scanGoExport(tx.QueryRow(ctx, `SELECT `+goExportColumns+` FROM cratectl.artifact_exports WHERE id=$1`, v.ID))
		if err != nil {
			return err
		}
		return appendEventIntent(ctx, tx, identity, "go.export.changed", out, true)
	})
	if err != nil {
		return GoExportSession{}, err
	}
	return out, nil
}
