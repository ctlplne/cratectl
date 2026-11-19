// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/debian"
	"github.com/jackc/pgx/v5"
)

const DebianReleaseMedia = "application/pgp-signed"

func decodeDebianRelease(a Artifact, distribution *debian.Distribution) (debian.Release, error) {
	var release debian.Release
	if a.Path != distribution.ReleasePath() || a.MediaType != DebianReleaseMedia || a.Size < 1 || a.Size > debian.MaxReleaseBytes ||
		!uploadDigest.MatchString(a.Digest) || len(a.Metadata) > 8<<10 || json.Unmarshal(a.Metadata, &release) != nil || !release.Matches(distribution) {
		return debian.Release{}, ErrConflict
	}
	return release, nil
}

func bindDebianRelease(ctx context.Context, tx pgx.Tx, i Identity, r Repository, release debian.Release, limit int, byteLimit int64) error {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if !release.Active(now) {
		return ErrConflict
	}
	distribution := r.Settings.DebianDistribution
	remaining := byteLimit
	for _, arch := range distribution.IndexArchitectures() {
		index, err := debianPackageIndexInTx(ctx, tx, i, r, arch, limit, remaining)
		if err != nil {
			return err
		}
		compressed, err := debian.GzipIndex(index)
		if err != nil {
			return err
		}
		if int64(len(compressed)) > byteLimit {
			return ErrMetadataLimit
		}
		plainPath, compressedPath := distribution.IndexPaths(arch)
		if release.Indexes[plainPath] != (debian.IndexDigest{SHA256: crypt.Digest(index), Size: int64(len(index))}) ||
			release.Indexes[compressedPath] != (debian.IndexDigest{SHA256: crypt.Digest(compressed), Size: int64(len(compressed))}) {
			return ErrConflict
		}
		remaining -= int64(len(index))
	}
	return nil
}

// PublishDebianRelease records an externally signed envelope only while its
// digest promises match the live index in the same tenant mutation. Stock APT
// verifies the signature against its independently installed public key.
func (s *Store) PublishDebianRelease(ctx context.Context, i Identity, repo string, a Artifact, limit int, byteLimit int64) error {
	if i.Role != "admin" {
		return ErrDenied
	}
	_, err := s.MutateRepository(ctx, i, repo, "", "", "apt.release.published", func(tx pgx.Tx) (any, int, error) {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return nil, 0, err
		}
		distribution := r.Settings.DebianDistribution
		release, err := decodeDebianRelease(a, distribution)
		if err != nil {
			return nil, 0, err
		}
		if err = bindDebianRelease(ctx, tx, i, r, release, limit, byteLimit); err != nil {
			return nil, 0, err
		}
		old := Artifact{Path: a.Path}
		err = tx.QueryRow(ctx, `SELECT digest,size,media_type,metadata FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo, a.Path).
			Scan(&old.Digest, &old.Size, &old.MediaType, &old.Metadata)
		if err == nil {
			previous, err := decodeDebianRelease(old, distribution)
			if err != nil || (old.Digest != a.Digest && !release.Issued.After(previous.Issued)) {
				return nil, 0, ErrConflict
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, err
		}
		sequence, err := nextEventSequence(ctx, tx, i)
		if err != nil {
			return nil, 0, err
		}
		replacement, err := prepareReferenceReplacement(ctx, tx, i, repo, a.Path, a.Digest, sequence)
		if err != nil {
			return nil, 0, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata) VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(tenant,repository,path) DO UPDATE SET digest=excluded.digest,size=excluded.size,media_type=excluded.media_type,metadata=excluded.metadata,
decision=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.decision ELSE 'unassessed' END,
created_at=CASE WHEN cratectl.artifacts.digest=excluded.digest THEN cratectl.artifacts.created_at ELSE now() END`,
			i.Tenant, repo, a.Path, a.Digest, a.Size, a.MediaType, a.Metadata)
		if err != nil {
			return nil, 0, err
		}
		if err = enqueueIntegrity(ctx, tx, i, repo, []Artifact{a}); err != nil {
			return nil, 0, err
		}
		event := map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "previous_digest": old.Digest, "size": a.Size,
			"issued_at": release.Issued, "valid_until": release.ValidUntil, "indexes": release.Indexes}
		if replacement != nil {
			event["reference_replacement"] = replacement
		}
		return event, 201, nil
	})
	return err
}

func (s *Store) DebianRelease(ctx context.Context, i Identity, repo string, limit int, byteLimit int64) (Artifact, error) {
	var a Artifact
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "apt" || r.Mode != "hosted" {
			return ErrConflict
		}
		distribution := r.Settings.DebianDistribution
		a, err = readArtifact(ctx, tx, repo, distribution.ReleasePath(), r.RequireReview, repositoryReadBudget(r))
		if err != nil {
			return err
		}
		release, err := decodeDebianRelease(a, distribution)
		if err != nil {
			return err
		}
		return bindDebianRelease(ctx, tx, i, r, release, limit, byteLimit)
	})
	return a, err
}
