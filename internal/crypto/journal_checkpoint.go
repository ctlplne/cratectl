// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
)

const JournalCheckpointProfile = "cratectl.journal.checkpoint.v1"
const JournalCheckpointPurpose = "tenant-journal-integrity"
const MaxJournalCheckpointStatement = 2048
const MaxJournalCheckpointPublicKey = 4096
const JournalCheckpointSignatureBytes = ed25519.SignatureSize

type JournalCheckpointStatement struct {
	Profile  string `json:"profile"`
	Purpose  string `json:"purpose"`
	Tenant   string `json:"tenant"`
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

// Prepare unsigned bytes only. Signing keys and signing operations stay with a
// customer-selected external tool/provider. This function confers no trust.
func JournalCheckpointBytes(anchor JournalAnchor) ([]byte, error) {
	if !anchor.Valid() {
		return nil, ErrJournalEvidence
	}
	raw, err := json.Marshal(JournalCheckpointStatement{JournalCheckpointProfile, JournalCheckpointPurpose, anchor.Tenant, anchor.Sequence, anchor.Hash})
	if err != nil || len(raw)+1 > MaxJournalCheckpointStatement {
		return nil, ErrJournalLimit
	}
	return append(raw, '\n'), nil
}

type JournalCheckpointVerification struct {
	Checkpoint        JournalAnchor `json:"checkpoint"`
	Profile           string        `json:"profile"`
	StatementSHA256   string        `json:"statement_sha256"`
	PublicKeySHA256   string        `json:"public_key_sha256"`
	SignatureVerified bool          `json:"signature_verified"`
}

// The caller supplies both the independently trusted public key and exact
// expected tenant/head. Neither is taken from the untrusted journal export.
func VerifyJournalCheckpoint(statement, signature, publicPEM []byte, expected JournalAnchor) (JournalCheckpointVerification, error) {
	if len(statement) > MaxJournalCheckpointStatement || len(publicPEM) > MaxJournalCheckpointPublicKey {
		return JournalCheckpointVerification{}, ErrJournalLimit
	}
	canonical, err := JournalCheckpointBytes(expected)
	if err != nil || !bytes.Equal(statement, canonical) || len(signature) != JournalCheckpointSignatureBytes || !bytes.HasPrefix(publicPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
		return JournalCheckpointVerification{}, ErrJournalEvidence
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil {
		return JournalCheckpointVerification{}, ErrJournalEvidence
	}
	defer clear(block.Bytes)
	if block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return JournalCheckpointVerification{}, ErrJournalEvidence
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, statement, signature) {
		return JournalCheckpointVerification{}, ErrJournalEvidence
	}
	return JournalCheckpointVerification{expected, JournalCheckpointProfile, Digest(statement), Digest(block.Bytes), true}, nil
}
