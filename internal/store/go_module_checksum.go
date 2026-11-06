// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/upstream"
)

// GoChecksumAuthority is explicitly configured trust, separate from package
// metadata. InitialCheckpoint bootstraps a new key, never resets a retained
// timeline. Public Go proxy creation remains gated until durable integration.
type GoChecksumAuthority struct {
	Endpoint          upstream.Config `json:"endpoint"`
	VerifierKey       string          `json:"verifier_key"`
	InitialCheckpoint []byte          `json:"initial_checkpoint"`
}

func (a GoChecksumAuthority) Validate() error {
	if a.Endpoint.AllowSignedQuery || a.Endpoint.CredentialRef != "" && !Name.MatchString(a.Endpoint.CredentialRef) {
		return crypt.ErrGoChecksumAuthority
	}
	if _, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint); err != nil {
		return err
	}
	endpoint, err := upstream.New(a.Endpoint, "")
	if err != nil {
		return err
	}
	endpoint.Close()
	return nil
}

const GoModuleChecksumProfile = "go-module-checksum-proof-v1"
const MaxGoModuleChecksumProof = 2 << 20

// GoModuleChecksumProof retains original log responses and both logical h1
// values. The bundle's raw SHA256 identities and current trust are separately
// supplied to admission; a proof's own key/checkpoint is never trust policy.
type GoModuleChecksumProof struct {
	Profile  string                `json:"profile"`
	Module   string                `json:"module"`
	Version  string                `json:"version"`
	ZIPHash  string                `json:"zip_h1"`
	ModHash  string                `json:"mod_h1"`
	Snapshot crypt.GoSumDBSnapshot `json:"snapshot"`
}

// Bound decoded values before JSON re-encoding or cryptographic replay. Exact
// canonical lookup/tile paths and per-response sizes remain crypto admission.
func validateGoChecksumProofShape(proof GoModuleChecksumProof, c gomodule.Coordinate, zipHash, modHash, key string) error {
	if proof.Profile != GoModuleChecksumProfile || proof.Module != c.Module || proof.Version != c.Version || proof.ZIPHash != zipHash || proof.ModHash != modHash || proof.Snapshot.VerifierKey != key || len(zipHash) != 47 || len(modHash) != 47 || len(key) > 4096 || len(proof.Snapshot.Checkpoint) == 0 || len(proof.Snapshot.Checkpoint) > 16<<10 || len(proof.Snapshot.Responses) == 0 || len(proof.Snapshot.Responses) > 128 {
		return ErrGoModuleUnvalidated
	}
	budget := 1 << 20
	for path, body := range proof.Snapshot.Responses {
		if len(path) > 2048 || len(path) > budget || len(body) > budget-len(path) {
			return ErrGoModuleUnvalidated
		}
		budget -= len(path) + len(body)
	}
	return nil
}

func VerifyGoModuleChecksumProof(ctx context.Context, proof GoModuleChecksumProof, c gomodule.Coordinate, zipHash, modHash, key string, checkpoint []byte) (crypt.GoSumDBVerification, error) {
	if _, err := gomodule.Canonical(c.Module, c.Version); err != nil || proof.Profile != GoModuleChecksumProfile || proof.Module != c.Module || proof.Version != c.Version || proof.ZIPHash != zipHash || proof.ModHash != modHash || proof.Snapshot.VerifierKey != key || !bytes.Equal(proof.Snapshot.Checkpoint, checkpoint) {
		return crypt.GoSumDBVerification{}, crypt.ErrGoChecksumAuthority
	}
	return crypt.VerifyGoSumDB(ctx, c.Module, c.Version, zipHash, modHash, proof.Snapshot)
}
