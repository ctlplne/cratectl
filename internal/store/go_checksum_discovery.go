// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

// Discovery grants routing metadata, never byte admission. An expired complete
// bundle must remain discoverable so a client can trigger its governed refresh.
// Check current receipt/key/proof policy in one bounded batch per source, without
// opening every proof object or querying the checksum authority over the network.
// Retain false entries: neither an upstream advertisement nor a lower-priority
// group member may replace a known but blocked coordinate.
func filterGoChecksumCandidatesInTx(ctx context.Context, tx pgx.Tx, r Repository, mod string, as []Artifact, candidates map[string]bool, budget *int64) error {
	if r.Settings.GoChecksumAuthority == nil && !r.Settings.Cache.RequireChecksum {
		return nil
	}
	allowed := make(map[string]bool, len(candidates))
	for v, ok := range candidates {
		allowed[v] = ok
		candidates[v] = false
	}
	authority := r.Settings.GoChecksumAuthority
	if authority == nil {
		return nil
	}
	*budget -= int64(len(authority.VerifierKey) + len(authority.InitialCheckpoint) + 192)
	if *budget < 0 {
		return ErrMetadataLimit
	}
	if err := authority.Validate(); err != nil {
		return err
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(authority.VerifierKey, authority.InitialCheckpoint)
	if err != nil {
		return err
	}
	if err := goChecksumAuthorityUsable(ctx, tx, initial.KeyDigest); err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}
	current, err := currentGoChecksumCheckpoint(ctx, tx, authority.VerifierKey, initial.KeyDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		// No accepted timeline means no accepted cached proof. A missing head
		// with retained history is rejected by currentGoChecksumCheckpoint.
		return nil
	}
	if err != nil {
		return err
	}
	*budget -= int64(len(current.Checkpoint) + 192)
	if *budget < 0 {
		return ErrMetadataLimit
	}
	bindings := map[string]map[string]string{}
	roots := make([]string, 0, len(candidates))
	for _, artifact := range as {
		m, err := ValidateGoModuleArtifact(artifact)
		if err != nil {
			return err
		}
		if _, exists := bindings[m.Version]; !exists {
			roots = append(roots, (gomodule.Coordinate{Module: mod, Version: m.Version}).Prefix()+".zip")
			bindings[m.Version] = m.Digests
		}
	}
	// Each receipt has one root/current validation generation. The immutable
	// accepted-history FK and exact current key witness publication trust; full
	// signed-head and original-proof replay are still mandatory before bytes.
	maxRows := min(len(candidates)+1, int(*budget/192)+1)
	rows, err := tx.Query(ctx, `SELECT c.version,left(c.root_path,2049),c.zip_digest,c.mod_digest,c.info_digest,
 left(a.digest,65),a.size,left(a.media_type,257),
 CASE WHEN octet_length(a.metadata::text)<=$7 THEN a.metadata ELSE NULL END,
 COALESCE(d.decision,a.decision),COALESCE(nl.deleted,false)
 FROM cratectl.go_module_checksum_receipts c
 JOIN cratectl.retrievals r ON (r.tenant,r.repository,r.path,r.source_revision,r.validation_generation)=(c.tenant,c.repository,c.root_path,c.source_revision,c.validation_generation)
 JOIN cratectl.retrievals m ON (m.tenant,m.repository,m.path,m.source_revision,m.validation_root,m.validation_generation)=(c.tenant,c.repository,left(c.root_path,-4)||'.mod',c.source_revision,c.root_path,c.validation_generation)
 JOIN cratectl.retrievals n ON (n.tenant,n.repository,n.path,n.source_revision,n.validation_root,n.validation_generation)=(c.tenant,c.repository,left(c.root_path,-4)||'.info',c.source_revision,c.root_path,c.validation_generation)
 JOIN cratectl.go_checksum_checkpoint_revisions h ON (h.tenant,h.key_digest,h.revision)=(c.tenant,c.key_digest,c.checkpoint_revision)
 JOIN cratectl.artifacts a ON (a.tenant,a.repository,a.path,a.digest,a.size)=(c.tenant,c.repository,c.proof_path,c.proof_digest,c.proof_size)
 `+decisionJoin+nativeLifecycleJoin+`
 WHERE c.repository=$1 AND c.module=$2 AND c.source_revision=$3 AND c.key_digest=$4 AND c.root_path=ANY($9::text[])
 AND h.verifier_key=$5 AND c.checkpoint_revision<=$6
 AND r.validation_root=c.root_path AND r.validation_generation>0 AND r.validation_generation<=r.generation
 AND ((r.state='ready' AND r.generation=r.validation_generation AND r.last_error='') OR (r.state='fetching' AND r.last_error IN ('','transient_upstream_failure')) OR (r.state='failed' AND r.last_error='transient_upstream_failure'))
 ORDER BY c.root_path LIMIT $8`, r.Name, mod, r.SourceRevision, initial.KeyDigest, authority.VerifierKey, current.Revision, min(int64(4096), *budget), maxRows, roots)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > len(candidates) {
			return ErrMetadataLimit
		}
		var version, root string
		var digests [3]string
		var proof Artifact
		if err := rows.Scan(&version, &root, &digests[0], &digests[1], &digests[2], &proof.Digest, &proof.Size, &proof.MediaType, &proof.Metadata, &proof.Decision, &proof.Deleted); err != nil {
			return err
		}
		*budget -= int64(len(version) + len(root) + len(digests[0]) + len(digests[1]) + len(digests[2]) + len(proof.Digest) + len(proof.MediaType) + len(proof.Metadata) + len(proof.Decision) + 192)
		if *budget < 0 || len(proof.Metadata) == 0 {
			return ErrMetadataLimit
		}
		c := gomodule.Coordinate{Module: mod, Version: version}
		binding := bindings[version]
		if !allowed[version] || root != c.Prefix()+".zip" || digests != [3]string{binding["zip"], binding["mod"], binding["info"]} || proof.Deleted || proof.Decision == "denied" {
			continue
		}
		if validateGoChecksumProofArtifact(proof, initial.KeyDigest) == nil {
			candidates[version] = true
		}
	}
	return rows.Err()
}

// Proofs are inert verification evidence. Unassessed evidence may be inspected;
// explicit denial/lifecycle is enforced separately from package review policy.
func validateGoChecksumProofArtifact(proof Artifact, keyDigest string) error {
	var metadata struct {
		Profile   string `json:"go_checksum_profile"`
		KeyDigest string `json:"go_checksum_key_digest"`
	}
	if proof.Size <= 0 || proof.Size > MaxGoModuleChecksumProof || proof.MediaType != GoChecksumProofMedia || len(proof.Metadata) > 4096 || json.Unmarshal(proof.Metadata, &metadata) != nil || metadata.Profile != GoModuleChecksumProfile || metadata.KeyDigest != keyDigest {
		return ErrGoModuleUnvalidated
	}
	return nil
}
