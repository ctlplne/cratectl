// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

type GoChecksumAuthorityState struct {
	Checkpoint           GoChecksumCheckpoint `json:"checkpoint"`
	CheckpointSHA256     string               `json:"checkpoint_sha256"`
	Blocked              bool                 `json:"blocked"`
	LegacyReviewRequired bool                 `json:"legacy_review_required"`
}

// Inspection does not authorize serving or expose another repository's module
// coordinates. A key block never deletes or replaces the retained signed head.
func (s *Store) GoChecksumState(ctx context.Context, i Identity, repo string, revision int64) (GoChecksumAuthorityState, error) {
	var out GoChecksumAuthorityState
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryRecordInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.SourceRevision != revision {
			return ErrSourceChanged
		}
		a := r.Settings.GoChecksumAuthority
		if r.Format != "go" || r.Mode != "proxy" || a == nil || a.Validate() != nil {
			return ErrGoModuleUnvalidated
		}
		initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
		if err != nil {
			return err
		}
		out.Checkpoint, err = currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
		if errors.Is(err, pgx.ErrNoRows) {
			out.Checkpoint = GoChecksumCheckpoint{KeyDigest: initial.KeyDigest, Checkpoint: bytes.Clone(a.InitialCheckpoint), TreeSize: initial.TreeSize, RootHash: initial.RootHash}
		} else if err != nil {
			return err
		}
		out.CheckpointSHA256 = crypt.Digest(out.Checkpoint.Checkpoint)
		out.Blocked, err = goChecksumKeyForked(ctx, tx, initial.KeyDigest)
		if err != nil {
			return err
		}
		out.LegacyReviewRequired, err = goChecksumLegacyReviewRequired(ctx, tx, initial.KeyDigest)
		return err
	})
	if err != nil {
		return GoChecksumAuthorityState{}, err
	}
	return out, nil
}

// Decode/verify log-misbehavior evidence using a separately supplied trust key.
// Attribution must separately match the digest in a trusted journal/export
// manifest; log signatures do not sign cratectl's tenant/repository metadata.
// This never grants package approval or verifies downstream delivery.
func VerifyGoChecksumFailureEvidence(ctx context.Context, raw []byte, key string) (GoChecksumFailureRecord, error) {
	if err := ctx.Err(); err != nil {
		return GoChecksumFailureRecord{}, err
	}
	if len(raw) == 0 || len(raw) > MaxGoChecksumFailureEvidence {
		return GoChecksumFailureRecord{}, ErrMetadataLimit
	}
	var r GoChecksumFailureRecord
	if json.Unmarshal(raw, &r) != nil || r.Profile != GoChecksumFailureEvidenceProfile || !Name.MatchString(r.Tenant) || !Name.MatchString(r.Repository) || r.SourceRevision < 0 || r.Generation <= 0 || r.ExpectedCheckpointRevision < 0 || r.CurrentCheckpointRevision < r.ExpectedCheckpointRevision || len(r.CurrentCheckpoint) > 16<<10 {
		return GoChecksumFailureRecord{}, ErrGoModuleUnvalidated
	}
	c, err := gomodule.Canonical(r.Report.Module, r.Report.Version)
	if err != nil || r.RootPath != c.Prefix()+".zip" || validateGoChecksumFailureReport(r.Report) != nil {
		return GoChecksumFailureRecord{}, ErrGoModuleUnvalidated
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(key, r.Report.Checkpoint)
	if err != nil || r.Report.VerifierKey != key || r.KeyDigest != initial.KeyDigest {
		return GoChecksumFailureRecord{}, crypt.ErrGoChecksumAuthority
	}
	if _, err = crypt.ParseGoSumDBCheckpoint(key, r.CurrentCheckpoint); err != nil {
		return GoChecksumFailureRecord{}, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) {
		return GoChecksumFailureRecord{}, ErrGoModuleUnvalidated
	}
	classification, err := classifyGoChecksumFailure(ctx, r.Report, key, r.Report.Checkpoint, r.CurrentCheckpoint)
	if err != nil {
		return GoChecksumFailureRecord{}, err
	}
	if classification != r.Classification {
		return GoChecksumFailureRecord{}, ErrGoModuleUnvalidated
	}
	return r, nil
}

// Raw upstream failure bodies may be sensitive. Historical evidence requires
// current tenant-administrator and underlying repository authorization.
// Exact bytes and their journal-bound digest are returned for offline export.
func (s *Store) GoChecksumFailureEvidence(ctx context.Context, i Identity, repo, root string, sourceRevision, generation int64) ([]byte, string, error) {
	request, err := gomodule.ParseRequest(root)
	if err != nil || request.Operation != "zip" || sourceRevision < 0 || generation <= 0 {
		return nil, "", ErrGoModuleUnvalidated
	}
	var raw []byte
	var digest string
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
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
		err = tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(evidence)<=$5 THEN evidence ELSE NULL END,evidence_digest FROM cratectl.go_checksum_failures WHERE repository=$1 AND root_path=$2 AND source_revision=$3 AND generation=$4`, repo, root, sourceRevision, generation, MaxGoChecksumFailureEvidence).Scan(&raw, &digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if len(raw) == 0 || crypt.Digest(raw) != digest {
			return ErrGoModuleUnvalidated
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return raw, digest, nil
}
