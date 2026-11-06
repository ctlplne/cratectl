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

// Neither a caller's verified flag nor a proof's own checkpoint grants trust.
// These bindings are populated by an authorized database snapshot and copied
// into an opaque token only after exact physical proof readback and verification.
type goChecksumBinding struct {
	tenant                                           string
	repository, rootPath                             string
	sourceRevision, generation, validationGeneration int64
	keyDigest, checkpointDigest                      string
	checkpointRevision                               int64
	proofDigest                                      string
	proofSize                                        int64
	module, version, zipHash, modHash                string
	rawDigests                                       [3]string
	rawSizes                                         [3]int64
	stale                                            bool
}

type GoModuleChecksumReadback struct {
	binding    goChecksumBinding
	key        string
	checkpoint []byte
	artifact   Artifact
}

// Object exposes only the exact immutable proof object to be opened with the
// common blob integrity check. Trust and package/lease bindings remain opaque.
func (v GoModuleChecksumReadback) Object() blob.Object {
	return blob.Object{Digest: v.binding.proofDigest, Size: v.binding.proofSize}
}

type GoChecksumAdmission struct{ binding goChecksumBinding }

// NativeAdmission preserves the root generation and explicitly validated stale
// context. It grants nothing until the final current SQL policy recheck.
func (a *GoChecksumAdmission) NativeAdmission() NativeAdmission {
	if a == nil {
		return NativeAdmission{}
	}
	b := a.binding
	return NativeAdmission{Repository: b.repository, Path: b.rootPath, Generation: b.generation, Stale: b.stale, GoChecksum: a}
}

// GoModuleChecksumReadback returns metadata for proof inspection only. It does
// not admit package bytes and cannot open configured proxy serving by itself.
func (s *Store) GoModuleChecksumReadback(ctx context.Context, i Identity, repository string, c gomodule.Coordinate, sourceRevision int64, admissions ...NativeAdmission) (GoModuleChecksumReadback, error) {
	if _, err := gomodule.Canonical(c.Module, c.Version); err != nil || sourceRevision < 0 || len(admissions) > 1 {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	var out GoModuleChecksumReadback
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repository, "read")
		if err != nil {
			return err
		}
		if r.SourceRevision != sourceRevision {
			return ErrSourceChanged
		}
		if r.Format != "go" || r.Mode != "proxy" || r.Settings.GoChecksumAuthority == nil {
			return ErrGoModuleUnvalidated
		}
		out, err = goChecksumReadbackInTx(ctx, tx, r, c.Prefix()+".zip", c, r.RequireReview, admissions)
		return err
	})
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	return out, nil
}

func goChecksumReadbackInTx(ctx context.Context, tx pgx.Tx, r Repository, p string, c gomodule.Coordinate, review bool, admissions []NativeAdmission) (GoModuleChecksumReadback, error) {
	a := r.Settings.GoChecksumAuthority
	if a == nil {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	if err := a.Validate(); err != nil {
		return GoModuleChecksumReadback{}, err
	}
	selected, err := goModuleProxyBundleInTx(ctx, tx, r, p, c, review, admissions)
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	m, err := ValidateGoModuleArtifact(selected)
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	if m.Module != c.Module || m.Version != c.Version {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	v := GoModuleChecksumReadback{key: a.VerifierKey, artifact: selected}
	b := &v.binding
	b.repository = r.Name
	b.rootPath = c.Prefix() + ".zip"
	b.sourceRevision = r.SourceRevision
	b.keyDigest = initial.KeyDigest
	b.module = c.Module
	b.version = c.Version
	if err = tx.QueryRow(ctx, `SELECT generation,validation_generation,tenant FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, r.Name, b.rootPath).Scan(&b.generation, &b.validationGeneration, &b.tenant); err != nil {
		return GoModuleChecksumReadback{}, err
	}
	if len(admissions) > 1 {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	if len(admissions) == 1 {
		admission := admissions[0]
		if admission.Repository != r.Name || admission.Path != b.rootPath || admission.Generation != b.generation {
			return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
		}
		b.stale = admission.Stale
	}
	var keyDigest, proofPath, module, version string
	err = tx.QueryRow(ctx, `SELECT key_digest,checkpoint_revision,proof_path,proof_digest,proof_size,module,version,zip_h1,mod_h1,zip_digest,mod_digest,info_digest FROM cratectl.go_module_checksum_receipts WHERE repository=$1 AND root_path=$2 AND source_revision=$3 AND validation_generation=$4`, r.Name, b.rootPath, r.SourceRevision, b.validationGeneration).Scan(&keyDigest, &b.checkpointRevision, &proofPath, &b.proofDigest, &b.proofSize, &module, &version, &b.zipHash, &b.modHash, &b.rawDigests[0], &b.rawDigests[1], &b.rawDigests[2])
	if errors.Is(err, pgx.ErrNoRows) {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	if keyDigest != initial.KeyDigest || module != c.Module || version != c.Version || proofPath != "go-checksum/"+b.proofDigest || b.rawDigests != [3]string{m.Digests["zip"], m.Digests["mod"], m.Digests["info"]} {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	for n, kind := range []string{"zip", "mod", "info"} {
		if err = tx.QueryRow(ctx, `SELECT size FROM cratectl.artifacts WHERE repository=$1 AND path=$2`, r.Name, c.Prefix()+"."+kind).Scan(&b.rawSizes[n]); err != nil {
			return GoModuleChecksumReadback{}, err
		}
	}
	current, err := currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	if b.checkpointRevision <= 0 || b.checkpointRevision > current.Revision {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	retained, err := retainedGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest, b.checkpointRevision)
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	v.checkpoint = bytes.Clone(retained.Checkpoint)
	b.checkpointDigest = crypt.Digest(v.checkpoint)
	// A retained proof is inert verification evidence, separate from package
	// approval. Unassessed proof evidence may be parsed/verified; current explicit
	// denial or logical deletion still blocks it through the common policy path.
	// Its immutable bytes can span source epochs, while this receipt cannot.
	budget := newGraphBudget()
	budget.sqlMetadataBytes = 4096
	proof, err := readArtifact(ctx, tx, r.Name, proofPath, false, budget)
	if err != nil {
		return GoModuleChecksumReadback{}, err
	}
	var metadata struct {
		Profile   string `json:"go_checksum_profile"`
		KeyDigest string `json:"go_checksum_key_digest"`
	}
	if proof.Digest != b.proofDigest || proof.Size != b.proofSize || proof.MediaType != GoChecksumProofMedia || len(proof.Metadata) > 4096 || json.Unmarshal(proof.Metadata, &metadata) != nil || metadata.Profile != GoModuleChecksumProfile || metadata.KeyDigest != initial.KeyDigest {
		return GoModuleChecksumReadback{}, ErrGoModuleUnvalidated
	}
	if err = validateGoChecksumReadback(v); err != nil {
		return GoModuleChecksumReadback{}, err
	}
	return v, nil
}

func validateGoChecksumReadback(v GoModuleChecksumReadback) error {
	b := v.binding
	c, err := gomodule.Canonical(b.module, b.version)
	if err != nil || !Name.MatchString(b.tenant) || !Name.MatchString(b.repository) || b.rootPath != c.Prefix()+".zip" || b.sourceRevision < 0 || b.generation <= 0 || b.validationGeneration <= 0 || b.validationGeneration > b.generation || b.checkpointRevision <= 0 || b.proofSize <= 0 || b.proofSize > MaxGoModuleChecksumProof {
		return ErrGoModuleUnvalidated
	}
	if err = (IntegrityTarget{Repository: b.repository, Path: "go-checksum/" + b.proofDigest, Digest: b.proofDigest, Size: b.proofSize}).Validate(); err != nil {
		return ErrGoModuleUnvalidated
	}
	for n, digest := range b.rawDigests {
		if err = (IntegrityTarget{Repository: b.repository, Path: b.rootPath, Digest: digest, Size: b.rawSizes[n]}).Validate(); err != nil {
			return ErrGoModuleUnvalidated
		}
	}
	pinned, err := crypt.ParseGoSumDBCheckpoint(v.key, v.checkpoint)
	if err != nil || pinned.KeyDigest != b.keyDigest || crypt.Digest(v.checkpoint) != b.checkpointDigest {
		return crypt.ErrGoChecksumAuthority
	}
	return nil
}

// VerifyGoModuleChecksumReadback accepts only the canonical typed JSON staged
// by publication. Re-encoding equality rejects duplicate/unknown/trailing fields
// and ambiguous encodings, while original response bytes remain intact inside
// the snapshot. The accepted history head, not the proof's own pin, is trust.
func VerifyGoModuleChecksumReadback(ctx context.Context, v GoModuleChecksumReadback, raw []byte) (*GoChecksumAdmission, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateGoChecksumReadback(v); err != nil {
		return nil, err
	}
	b := v.binding
	if len(raw) > MaxGoModuleChecksumProof || int64(len(raw)) != b.proofSize || crypt.Digest(raw) != b.proofDigest {
		return nil, ErrGoModuleUnvalidated
	}
	var proof GoModuleChecksumProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		return nil, ErrGoModuleUnvalidated
	}
	if err := validateGoChecksumProofShape(proof, gomodule.Coordinate{Module: b.module, Version: b.version}, b.zipHash, b.modHash, v.key); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrGoModuleUnvalidated
	}
	original, err := crypt.ParseGoSumDBCheckpoint(v.key, proof.Snapshot.Checkpoint)
	if err != nil {
		return nil, err
	}
	accepted, err := crypt.ParseGoSumDBCheckpoint(v.key, v.checkpoint)
	if err != nil || original.TreeSize > accepted.TreeSize {
		return nil, crypt.ErrGoChecksumAuthority
	}
	if original.TreeSize == accepted.TreeSize && original.RootHash != accepted.RootHash {
		return nil, crypt.ErrGoChecksumFork
	}
	if proof.Snapshot.VerifierKey != v.key {
		return nil, crypt.ErrGoChecksumAuthority
	}
	proof.Snapshot.Checkpoint = bytes.Clone(v.checkpoint)
	_, err = VerifyGoModuleChecksumProof(ctx, proof, gomodule.Coordinate{Module: b.module, Version: b.version}, b.zipHash, b.modHash, v.key, v.checkpoint)
	if err != nil {
		return nil, err
	}
	return &GoChecksumAdmission{binding: b}, nil
}
