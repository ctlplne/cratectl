// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type referenceReplacement struct {
	Previous ArtifactState `json:"previous"`
	Current  ArtifactState `json:"current"`
}

// Called under the tenant write lock, before replacing a mutable reference.
// The caller must include the returned snapshot in its publication event in the
// same transaction. Historical hold receipts keep their original digest/revision.
func prepareReferenceReplacement(ctx context.Context, tx pgx.Tx, i Identity, repo, path, digest string, sequence int64) (*referenceReplacement, error) {
	previous, e := artifactStateInTx(ctx, tx, repo, path)
	if e != nil {
		return nil, e
	}
	if previous.Deleted {
		return nil, ErrDeleted
	}
	if previous.Revision == 0 {
		return nil, nil
	}
	var bound string
	if e = tx.QueryRow(ctx, `SELECT digest FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, path).Scan(&bound); e != nil {
		return nil, e
	}
	if previous.Digest != bound {
		return nil, ErrLifecycleRevision
	}
	if previous.Digest == digest {
		return nil, nil
	}
	if previous.Held {
		return nil, ErrHeld
	}
	_, e = tx.Exec(ctx, `UPDATE cratectl.artifact_lifecycle SET digest=$3,revision=revision+1,hold_reason='',hold_until=NULL,reason='reference bytes replaced',actor=$4,change_sequence=$5,changed_at=clock_timestamp() WHERE repository=$1 AND path=$2`, repo, path, digest, i.Actor, sequence)
	if e != nil {
		return nil, e
	}
	current, e := artifactStateInTx(ctx, tx, repo, path)
	return &referenceReplacement{Previous: previous, Current: current}, e
}
