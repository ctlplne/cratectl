// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The history projection deliberately excludes original upstream bodies, keys
// and signed pins. Sequence is a tenant journal position, not proof of delivery.
type GoChecksumFailureSummary struct {
	RootPath                   string    `json:"root_path"`
	SourceRevision             int64     `json:"source_revision"`
	Generation                 int64     `json:"generation"`
	KeyDigest                  string    `json:"key_digest"`
	ExpectedCheckpointRevision int64     `json:"expected_checkpoint_revision"`
	Classification             string    `json:"classification"`
	EvidenceDigest             string    `json:"evidence_sha256"`
	Sequence                   int64     `json:"sequence"`
	CreatedAt                  time.Time `json:"created_at"`
}

// Historical inspection remains available for a suspended or removed record.
// Current credentials, tenant administrator role and repository access still
// apply. A page has at most 100 fixed-size summaries; no evidence blob is read.
func (s *Store) GoChecksumFailurePage(ctx context.Context, i Identity, repo string, after int64, limit int) ([]GoChecksumFailureSummary, bool, error) {
	if !Name.MatchString(repo) || after < 0 || limit < 1 || limit > 100 {
		return nil, false, ErrConflict
	}
	out := []GoChecksumFailureSummary{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryRecordInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if i.Role != "admin" {
			return ErrDenied
		}
		if r.Format != "go" || r.Mode != "proxy" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT root_path,source_revision,generation,key_digest,expected_checkpoint_revision,classification,evidence_digest,change_sequence,created_at FROM cratectl.go_checksum_failures WHERE repository=$1 AND change_sequence>$2 ORDER BY change_sequence LIMIT $3`, repo, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v GoChecksumFailureSummary
			if err := rows.Scan(&v.RootPath, &v.SourceRevision, &v.Generation, &v.KeyDigest, &v.ExpectedCheckpointRevision, &v.Classification, &v.EvidenceDigest, &v.Sequence, &v.CreatedAt); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}
