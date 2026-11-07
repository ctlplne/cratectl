// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

var ErrGoChecksumCheckpointChanged = errors.New("Go checksum checkpoint changed; recollect bounded proof against current trust")

const GoChecksumProofMedia = "application/vnd.cratectl.go-checksum-proof.v1+json"

// Hashes are computed from the inspected ZIP and go.mod before staging. They
// are separate from the untrusted proof and the three raw object identities.
type GoModuleChecksumPublication struct {
	Proof                      GoModuleChecksumProof
	Object                     blob.Object
	ZIPHash, ModHash           string
	ExpectedCheckpointRevision int64
}

type GoChecksumCheckpoint struct {
	KeyDigest  string `json:"key_digest"`
	Revision   int64  `json:"revision"`
	Checkpoint []byte `json:"checkpoint"`
	TreeSize   int64  `json:"tree_size"`
	RootHash   string `json:"root_hash"`
}

// GoModuleChecksumCheckpoint authorizes the repository and source epoch in one
// snapshot. Revision zero means explicit bootstrap, never a missing-history
// fallback. Only log heads are shared between repositories, not package proofs.
func (s *Store) GoModuleChecksumCheckpoint(ctx context.Context, i Identity, repository string, sourceRevision int64) (GoChecksumCheckpoint, error) {
	var out GoChecksumCheckpoint
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repository, "read")
		if err != nil {
			return err
		}
		if r.SourceRevision != sourceRevision {
			return ErrSourceChanged
		}
		a := r.Settings.GoChecksumAuthority
		if r.Format != "go" || r.Mode != "proxy" || a == nil {
			return ErrGoModuleUnvalidated
		}
		if err := a.Validate(); err != nil {
			return err
		}
		initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
		if err != nil {
			return err
		}
		if err := goChecksumAuthorityUsable(ctx, tx, initial.KeyDigest); err != nil {
			return err
		}
		out, err = currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
		if errors.Is(err, pgx.ErrNoRows) {
			out = GoChecksumCheckpoint{KeyDigest: initial.KeyDigest, Checkpoint: bytes.Clone(a.InitialCheckpoint), TreeSize: initial.TreeSize, RootHash: initial.RootHash}
			return nil
		}
		return err
	})
	if err != nil {
		return GoChecksumCheckpoint{}, err
	}
	return out, nil
}

func currentGoChecksumCheckpoint(ctx context.Context, tx pgx.Tx, key, digest string) (GoChecksumCheckpoint, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM cratectl.go_checksum_checkpoints WHERE key_digest=$1`, digest).Scan(&revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var retained bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.go_checksum_checkpoint_revisions WHERE key_digest=$1)`, digest).Scan(&retained); e != nil {
				return GoChecksumCheckpoint{}, e
			}
			if retained {
				return GoChecksumCheckpoint{}, crypt.ErrGoChecksumAuthority
			}
		}
		return GoChecksumCheckpoint{}, err
	}
	out, err := retainedGoChecksumCheckpoint(ctx, tx, key, digest, revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return GoChecksumCheckpoint{}, crypt.ErrGoChecksumAuthority
	}
	return out, err
}

func retainedGoChecksumCheckpoint(ctx context.Context, tx pgx.Tx, key, digest string, revision int64) (GoChecksumCheckpoint, error) {
	out := GoChecksumCheckpoint{KeyDigest: digest, Revision: revision}
	var retainedKey, authority string
	err := tx.QueryRow(ctx, `SELECT verifier_key,authority,checkpoint,tree_size,root_hash FROM cratectl.go_checksum_checkpoint_revisions WHERE key_digest=$1 AND revision=$2`, digest, revision).Scan(&retainedKey, &authority, &out.Checkpoint, &out.TreeSize, &out.RootHash)
	if err != nil {
		return GoChecksumCheckpoint{}, err
	}
	parsed, err := crypt.ParseGoSumDBCheckpoint(key, out.Checkpoint)
	if err != nil || retainedKey != key || parsed.KeyDigest != digest || parsed.Authority != authority || parsed.TreeSize != out.TreeSize || parsed.RootHash != out.RootHash {
		return GoChecksumCheckpoint{}, crypt.ErrGoChecksumAuthority
	}
	return out, nil
}

func validateGoChecksumPublication(repo Repository, p *GoModuleChecksumPublication, c gomodule.Coordinate) error {
	a := repo.Settings.GoChecksumAuthority
	if a == nil {
		if p != nil || repo.Settings.Cache.RequireChecksum {
			return ErrGoModuleUnvalidated
		}
		return nil
	}
	if p == nil || p.ExpectedCheckpointRevision < 0 {
		return ErrGoModuleUnvalidated
	}
	if err := validateGoChecksumProofShape(p.Proof, c, p.ZIPHash, p.ModHash, a.VerifierKey); err != nil {
		return err
	}
	raw, err := json.Marshal(p.Proof)
	if err != nil || len(raw) > MaxGoModuleChecksumProof || p.Object.Size != int64(len(raw)) || p.Object.Digest != crypt.Digest(raw) {
		return ErrGoModuleUnvalidated
	}
	return nil
}

// Rebase only after the original proof has authenticated against its separately
// retained expected pin. No network is possible here. An identical winner
// coalesces; missing consistency tiles require a new bounded collection.
func rebaseGoChecksumProof(ctx context.Context, p GoModuleChecksumPublication, c gomodule.Coordinate, key string, expected, current []byte) (crypt.GoSumDBVerification, error) {
	verified, err := VerifyGoModuleChecksumProof(ctx, p.Proof, c, p.ZIPHash, p.ModHash, key, expected)
	if err != nil {
		return crypt.GoSumDBVerification{}, err
	}
	if bytes.Equal(expected, current) {
		return verified, nil
	}
	snapshot := p.Proof.Snapshot
	snapshot.Checkpoint = current
	verified, err = crypt.VerifyGoSumDB(ctx, c.Module, c.Version, p.ZIPHash, p.ModHash, snapshot)
	if errors.Is(err, crypt.ErrGoChecksumFork) || ctx.Err() != nil {
		return crypt.GoSumDBVerification{}, err
	}
	if err != nil {
		return crypt.GoSumDBVerification{}, ErrGoChecksumCheckpointChanged
	}
	return verified, nil
}

func appendGoChecksumCheckpoint(ctx context.Context, tx pgx.Tx, i Identity, key string, revision, sequence int64, checkpoint []byte) (GoChecksumCheckpoint, error) {
	parsed, err := crypt.ParseGoSumDBCheckpoint(key, checkpoint)
	if err != nil {
		return GoChecksumCheckpoint{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_checkpoint_revisions(tenant,key_digest,revision,verifier_key,authority,checkpoint,tree_size,root_hash,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, i.Tenant, parsed.KeyDigest, revision, key, parsed.Authority, checkpoint, parsed.TreeSize, parsed.RootHash, sequence)
	if err != nil {
		return GoChecksumCheckpoint{}, err
	}
	if revision == 1 {
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_checkpoints(tenant,key_digest,revision) VALUES($1,$2,$3)`, i.Tenant, parsed.KeyDigest, revision)
	} else {
		tag, e := tx.Exec(ctx, `UPDATE cratectl.go_checksum_checkpoints SET revision=$1 WHERE key_digest=$2 AND revision=$3`, revision, parsed.KeyDigest, revision-1)
		err = e
		if err == nil && tag.RowsAffected() != 1 {
			err = ErrGoChecksumCheckpointChanged
		}
	}
	return GoChecksumCheckpoint{KeyDigest: parsed.KeyDigest, Revision: revision, Checkpoint: bytes.Clone(checkpoint), TreeSize: parsed.TreeSize, RootHash: parsed.RootHash}, err
}

// Called only in CompleteRetrieval's tenant write lock and current lease/source
// transaction. All heads, immutable proof references, receipts, sibling refs,
// integrity intents and the ready event either commit together or roll back.
func completeGoChecksumPublication(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, lease Retrieval, result RetrievalResult, sequence int64) (Artifact, error) {
	p := *result.GoModule.Checksum
	a := repo.Settings.GoChecksumAuthority
	if a == nil {
		return Artifact{}, ErrGoModuleUnvalidated
	}
	if err := a.Validate(); err != nil {
		return Artifact{}, err
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
	if err != nil {
		return Artifact{}, err
	}
	if err := goChecksumAuthorityUsable(ctx, tx, initial.KeyDigest); err != nil {
		return Artifact{}, err
	}
	current, err := currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		current = GoChecksumCheckpoint{KeyDigest: initial.KeyDigest, Checkpoint: bytes.Clone(a.InitialCheckpoint), TreeSize: initial.TreeSize, RootHash: initial.RootHash}
	} else if err != nil {
		return Artifact{}, err
	}
	if p.ExpectedCheckpointRevision > current.Revision {
		return Artifact{}, ErrGoChecksumCheckpointChanged
	}
	expected := a.InitialCheckpoint
	if p.ExpectedCheckpointRevision > 0 {
		retained, e := retainedGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest, p.ExpectedCheckpointRevision)
		if e != nil {
			return Artifact{}, e
		}
		expected = retained.Checkpoint
	}
	c := gomodule.Coordinate{Module: p.Proof.Module, Version: p.Proof.Version}
	verified, err := rebaseGoChecksumProof(ctx, p, c, a.VerifierKey, expected, current.Checkpoint)
	if err != nil {
		return Artifact{}, err
	}
	proposed, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, verified.Checkpoint)
	if err != nil {
		return Artifact{}, err
	}
	if proposed.TreeSize < current.TreeSize {
		return Artifact{}, crypt.ErrGoChecksumAuthority
	}
	if current.Revision == 0 {
		current, err = appendGoChecksumCheckpoint(ctx, tx, i, a.VerifierKey, 1, sequence, current.Checkpoint)
		if err != nil {
			return Artifact{}, err
		}
	}
	if proposed.TreeSize != current.TreeSize || proposed.RootHash != current.RootHash {
		if proposed.TreeSize == current.TreeSize {
			return Artifact{}, crypt.ErrGoChecksumFork
		}
		current, err = appendGoChecksumCheckpoint(ctx, tx, i, a.VerifierKey, current.Revision+1, sequence, verified.Checkpoint)
		if err != nil {
			return Artifact{}, err
		}
	}
	proof := Artifact{Repository: repo.Name, Path: "go-checksum/" + p.Object.Digest, Digest: p.Object.Digest, Size: p.Object.Size, MediaType: GoChecksumProofMedia}
	proof.Metadata, _ = json.Marshal(map[string]any{"go_checksum_profile": GoModuleChecksumProfile, "go_checksum_key_digest": initial.KeyDigest})
	if err = notDeletedInTx(ctx, tx, repo.Name, proof.Path); err != nil {
		return Artifact{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,source_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, i.Tenant, repo.Name, proof.Path, proof.Digest, proof.Size, proof.MediaType, proof.Metadata, lease.SourceRevision)
	if err != nil {
		return Artifact{}, err
	}
	var bound bool
	err = tx.QueryRow(ctx, `SELECT digest=$3 AND size=$4 AND media_type=$5 FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, repo.Name, proof.Path, proof.Digest, proof.Size, proof.MediaType).Scan(&bound)
	if err != nil {
		return Artifact{}, err
	}
	if !bound {
		return Artifact{}, ErrConflict
	}
	m, err := validateGoModuleBundle(result.GoModule.Objects)
	if err != nil {
		return Artifact{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cratectl.go_module_checksum_receipts(tenant,repository,root_path,source_revision,validation_generation,key_digest,checkpoint_revision,expected_checkpoint_revision,proof_path,proof_digest,proof_size,module,version,zip_h1,mod_h1,zip_digest,mod_digest,info_digest,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, i.Tenant, repo.Name, lease.Path, lease.SourceRevision, lease.Generation, initial.KeyDigest, current.Revision, p.ExpectedCheckpointRevision, proof.Path, proof.Digest, proof.Size, c.Module, c.Version, p.ZIPHash, p.ModHash, m.Digests["zip"], m.Digests["mod"], m.Digests["info"], sequence)
	return proof, err
}
