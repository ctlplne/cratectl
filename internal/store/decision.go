// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
)

const artifactColumns = `a.repository,a.path,a.digest,a.size,a.media_type,a.metadata,COALESCE(d.decision,a.decision),a.created_at`
const decisionJoin = ` LEFT JOIN cratectl.content_decisions d ON (d.tenant,d.repository,d.digest)=(a.tenant,a.repository,a.digest) `

// Decide binds a manual judgment to bytes in this repository, covering current
// and future coordinate aliases. The path is a checked selector, not the scope.
func Decide(ctx context.Context, tx pgx.Tx, i Identity, repo, path, digest, decision string) (any, error) {
	if i.Role != "admin" {
		return nil, ErrDenied
	}
	if len(digest) != 64 {
		return nil, ErrConflict
	}
	if _, e := hex.DecodeString(digest); e != nil {
		return nil, ErrConflict
	}
	var exists bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2 AND digest=$3)`, repo, path, digest).Scan(&exists); e != nil {
		return nil, e
	}
	if !exists {
		return nil, ErrNotFound
	}
	if decision != "allowed" && decision != "denied" {
		return nil, ErrConflict
	}
	var version int64
	e := tx.QueryRow(ctx, `INSERT INTO cratectl.content_decisions(tenant,repository,digest,decision) VALUES($1,$2,$3,$4) ON CONFLICT(tenant,repository,digest) DO UPDATE SET decision=excluded.decision,version=cratectl.content_decisions.version+1,updated_at=now() RETURNING version`, i.Tenant, repo, digest, decision).Scan(&version)
	if e != nil {
		return nil, e
	}
	tag, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision=$1 WHERE repository=$2 AND digest=$3`, decision, repo, digest)
	if e != nil {
		return nil, e
	}
	return map[string]any{"repository": repo, "path": path, "digest": digest, "decision": decision, "evidence_kind": "manual", "scope": "repository_digest", "decision_version": version, "affected_references": tag.RowsAffected()}, nil
}
