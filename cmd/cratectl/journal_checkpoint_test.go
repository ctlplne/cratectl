// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type journalSignedUnitFixture struct {
	Head                                    crypt.JournalAnchor
	Statement, Signature, PublicKey, Export []byte
}

func journalSignedCLI(t *testing.T) journalSignedUnitFixture {
	t.Helper()
	raw, err := os.ReadFile("../../internal/crypto/testdata/journal-checkpoint-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture journalSignedUnitFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestJournalCheckpointPreparationIsCanonicalAndUnsigned(t *testing.T) {
	fixture := journalSignedCLI(t)
	args := []string{"--tenant", fixture.Head.Tenant, "--through", strconv.FormatInt(fixture.Head.Sequence, 10), "--through-hash", fixture.Head.Hash}
	var out bytes.Buffer
	if err := runJournalCheckpoint(args, &out); err != nil || !bytes.Equal(out.Bytes(), fixture.Statement) {
		t.Fatal("prepared statement changed or conferred trust", err)
	}
	for _, bad := range [][]string{nil, {"--tenant", "owned-team", "--through", "01", "--through-hash", fixture.Head.Hash}, append(args, "unexpected"), {"--tenant", "another.team", "--through", "0"}} {
		out.Reset()
		if err := runJournalCheckpoint(bad, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid checkpoint preparation succeeded", err)
		}
	}
}

func TestJournalOfflineSignatureFilesRequireIndependentKeyAndExactTerminalBindings(t *testing.T) {
	f := journalSignedCLI(t)
	for _, scenario := range []string{"signed", "manual", "wrong-key", "bad-signature", "altered-statement", "wrong-tenant", "wrong-head", "partial-flags", "missing-signature", "public-statement", "private-key", "extra-pem", "truncated-export", "bad-export-before-config"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			statement, signature, key, export := append([]byte(nil), f.Statement...), append([]byte(nil), f.Signature...), append([]byte(nil), f.PublicKey...), append([]byte(nil), f.Export...)
			switch scenario {
			case "wrong-key":
				index := bytes.IndexByte(key, '\n') + 41
				if key[index] == 'A' {
					key[index] = 'B'
				} else {
					key[index] = 'A'
				}
			case "bad-signature", "bad-export-before-config":
				signature[0] ^= 1
			case "altered-statement":
				statement = bytes.ReplaceAll(statement, []byte("owned-team"), []byte("other-team"))
			case "private-key":
				key = bytes.ReplaceAll(key, []byte("PUBLIC KEY"), []byte("PRIVATE KEY"))
			case "extra-pem":
				key = append(key, key...)
			case "truncated-export":
				export = export[:len(export)-1]
			}
			for name, raw := range map[string][]byte{"statement.json": statement, "signature.bin": signature, "key.pem": key, "export.jsonl": export} {
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "public-statement" {
				if err := os.Chmod(filepath.Join(dir, "statement.json"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "missing-signature" {
				if err := os.Remove(filepath.Join(dir, "signature.bin")); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--export-file", filepath.Join(dir, "export.jsonl"), "--tenant", f.Head.Tenant, "--through", "1", "--through-hash", f.Head.Hash}
			if scenario == "wrong-tenant" {
				args[3] = "another-team"
			}
			if scenario == "wrong-head" {
				args[7] = strings.Repeat("a", 64)
			}
			flags := []string{"--checkpoint-file", filepath.Join(dir, "statement.json"), "--checkpoint-signature-file", filepath.Join(dir, "signature.bin"), "--checkpoint-key-file", filepath.Join(dir, "key.pem")}
			if scenario == "partial-flags" {
				flags = flags[:2]
			}
			if scenario != "manual" {
				args = append(args, flags...)
			}
			var out bytes.Buffer
			if scenario == "bad-export-before-config" {
				output := filepath.Join(dir, "new-output.jsonl")
				args = append([]string{"--config", filepath.Join(dir, "missing-config.json"), "--output", output, "--tenant", f.Head.Tenant, "--through", "1", "--through-hash", f.Head.Hash}, flags...)
				err := runJournalExport(args, &out)
				if err == nil || !strings.Contains(err.Error(), "signature did not verify") || out.Len() != 0 {
					t.Fatal("invalid signature reached config/network/output", err)
				}
				if _, err := os.Lstat(output); !os.IsNotExist(err) {
					t.Fatal("unverified collection created output")
				}
				return
			}
			err := runJournalVerify(args, &out)
			if scenario == "signed" || scenario == "manual" {
				var result struct {
					crypt.JournalVerification
					Signature *crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
					Trust     string
				}
				if err != nil || json.Unmarshal(out.Bytes(), &result) != nil || !result.MatchesSuppliedCheckpoint || result.Events != 1 || (result.Signature != nil) != (scenario == "signed") || result.Trust == "" {
					t.Fatal("signature mode lost distinct outcome", err)
				}
				if result.Signature != nil && (!result.Signature.SignatureVerified || result.Signature.Checkpoint != f.Head) {
					t.Fatal("unbound checkpoint signature receipt")
				}
			} else if err == nil || out.Len() != 0 {
				t.Fatal("invalid signed export emitted a receipt", scenario, err)
			}
		})
	}
}
