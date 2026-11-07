// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func signedJournalCheckpointFixture(t testing.TB) (JournalAnchor, []byte, []byte, []byte) {
	t.Helper()
	// An intentionally public deterministic unit fixture; no customer key is
	// generated, persisted or accepted by the product's verification interface.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	defer clear(key)
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	anchor := JournalAnchor{Tenant: "owned-team", Sequence: 7, Hash: strings.Repeat("a", 64)}
	statement, err := JournalCheckpointBytes(anchor)
	if err != nil {
		t.Fatal(err)
	}
	return anchor, statement, ed25519.Sign(key, statement), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
}

func TestJournalCheckpointSignatureBindsExactPurposeTenantHeadAndExternalKey(t *testing.T) {
	for _, scenario := range []string{"valid", "valid-genesis", "tenant", "sequence", "hash", "purpose", "profile", "field-order", "unknown", "duplicate", "case-alias", "null", "missing-newline", "extra-newline", "signature", "short-signature", "long-signature", "wrong-key", "different-algorithm", "private-key", "extra-pem", "pem-header", "leading-pem-data", "statement-limit", "key-limit", "genesis"} {
		t.Run(scenario, func(t *testing.T) {
			anchor, raw, signature, key := signedJournalCheckpointFixture(t)
			want := ErrJournalEvidence
			switch scenario {
			case "valid-genesis":
				anchor.Sequence, anchor.Hash = 0, ""
				raw, _ = JournalCheckpointBytes(anchor)
			case "tenant":
				anchor.Tenant = "another-team"
			case "sequence":
				anchor.Sequence++
			case "hash":
				anchor.Hash = strings.Repeat("b", 64)
			case "purpose":
				raw = bytes.ReplaceAll(raw, []byte(JournalCheckpointPurpose), []byte("artifact-approval"))
			case "profile":
				raw = bytes.ReplaceAll(raw, []byte(JournalCheckpointProfile), []byte("unrelated.protocol.v1"))
			case "field-order":
				raw = bytes.Replace(raw, []byte(`"profile":"`+JournalCheckpointProfile+`","purpose":"`+JournalCheckpointPurpose+`"`), []byte(`"purpose":"`+JournalCheckpointPurpose+`","profile":"`+JournalCheckpointProfile+`"`), 1)
			case "unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"tenant":"owned-team",`), raw[1:]...)
			case "case-alias":
				raw = bytes.Replace(raw, []byte(`"tenant"`), []byte(`"Tenant"`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"owned-team"`), []byte(`null`), 1)
			case "missing-newline":
				raw = raw[:len(raw)-1]
			case "extra-newline":
				raw = append(raw, '\n')
			case "signature":
				signature[0] ^= 1
			case "short-signature":
				signature = signature[:63]
			case "long-signature":
				signature = append(signature, 0)
			case "wrong-key":
				other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, ed25519.SeedSize))
				defer clear(other)
				der, err := x509.MarshalPKIXPublicKey(other.Public())
				if err != nil {
					t.Fatal(err)
				}
				key = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			case "private-key":
				key = bytes.ReplaceAll(key, []byte("PUBLIC KEY"), []byte("PRIVATE KEY"))
			case "different-algorithm":
				block, _ := pem.Decode(key)
				block.Bytes = bytes.Replace(block.Bytes, []byte{6, 3, 43, 101, 112}, []byte{6, 3, 43, 101, 110}, 1)
				key = pem.EncodeToMemory(block)
			case "extra-pem":
				key = append(key, key...)
			case "pem-header":
				block, _ := pem.Decode(key)
				block.Headers = map[string]string{"Owned": "unexpected"}
				key = pem.EncodeToMemory(block)
			case "leading-pem-data":
				key = append([]byte("untrusted prefix\n"), key...)
			case "statement-limit":
				raw = bytes.Repeat([]byte("x"), MaxJournalCheckpointStatement+1)
				want = ErrJournalLimit
			case "key-limit":
				key = bytes.Repeat([]byte("x"), MaxJournalCheckpointPublicKey+1)
				want = ErrJournalLimit
			case "genesis":
				anchor.Sequence, anchor.Hash = 0, "" // Old signed non-genesis bytes cannot authenticate genesis.
			}
			// Malformed or purpose-altered statements are signed by the trusted
			// unit fixture key too: signature validity alone must not admit them.
			switch scenario {
			case "valid-genesis", "purpose", "profile", "field-order", "unknown", "duplicate", "case-alias", "null", "missing-newline", "extra-newline":
				private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
				signature = ed25519.Sign(private, raw)
				clear(private)
			}
			result, err := VerifyJournalCheckpoint(raw, signature, key, anchor)
			if scenario == "valid" || scenario == "valid-genesis" {
				trusted, _ := pem.Decode(key)
				if err != nil || !result.SignatureVerified || result.Checkpoint != anchor || result.StatementSHA256 != Digest(raw) || trusted == nil || result.PublicKeySHA256 != Digest(trusted.Bytes) {
					t.Fatal("signed unit fixture refused", err)
				}
			} else if !errors.Is(err, want) || !reflect.DeepEqual(result, JournalCheckpointVerification{}) {
				t.Fatal("untrusted checkpoint returned success", scenario, err)
			}
		})
	}
}

func FuzzJournalCheckpointSignatureBindings(f *testing.F) {
	anchor, raw, sig, key := signedJournalCheckpointFixture(f)
	f.Add(raw, sig, key)
	f.Add([]byte("null\n"), []byte("invalid"), []byte("invalid"))
	f.Fuzz(func(t *testing.T, statement, signature, public []byte) {
		if len(statement) > 8192 || len(signature) > 128 || len(public) > 8192 {
			return
		}
		result, err := VerifyJournalCheckpoint(statement, signature, public, anchor)
		if err == nil && (!result.SignatureVerified || result.Checkpoint != anchor || !bytes.Equal(statement, raw)) {
			t.Fatal("unbound signature accepted")
		}
	})
}
