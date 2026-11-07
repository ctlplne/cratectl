// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type checksumJournalPublicFixture struct {
	Head                                     crypt.JournalAnchor
	Evidence                                 []byte
	GoKey                                    string
	Journal, Statement, Signature, PublicKey []byte
}

func readChecksumJournalPublicFixture(t *testing.T, name string) checksumJournalPublicFixture {
	t.Helper()
	raw, err := os.ReadFile("../../internal/crypto/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var encoded struct {
		Head                         crypt.JournalAnchor
		Evidence, Journal, Statement json.RawMessage
		GoKey, PublicKey             string
		Signature                    []byte
	}
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatal(err)
	}
	compact := func(input []byte, newline bool) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := json.Compact(&out, input); err != nil {
			t.Fatal(err)
		}
		if newline {
			out.WriteByte('\n')
		}
		return out.Bytes()
	}
	// The fixture stores the public key, not a redundant fingerprint that secret
	// scanners can mistake for a credential. Reconstruct exactly the original
	// canonical record; the signed journal's digest independently checks it.
	var authority struct {
		Report struct {
			Checkpoint []byte `json:"checkpoint"`
		} `json:"report"`
	}
	if err := json.Unmarshal(encoded.Evidence, &authority); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := crypt.ParseGoSumDBCheckpoint(encoded.GoKey, authority.Report.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	evidence := compact(encoded.Evidence, false)
	marker := []byte(`"key_digest":"derive-public-authority-key"`)
	if bytes.Count(evidence, marker) != 1 {
		t.Fatal("public fingerprint fixture must use one explicit derivation")
	}
	evidence = bytes.Replace(evidence, marker, []byte(`"key_digest":"`+checkpoint.KeyDigest+`"`), 1)
	return checksumJournalPublicFixture{encoded.Head, evidence, encoded.GoKey, compact(encoded.Journal, true), compact(encoded.Statement, true), encoded.Signature, []byte(encoded.PublicKey)}
}

func TestOfflineChecksumJournalRequiresSignedCompleteRangeAndExactOriginalBinding(t *testing.T) {
	fixture := readChecksumJournalPublicFixture(t, "go-checksum-journal-public.json")
	for _, scenario := range []string{"signed", "manual-and-journal", "manual-disagrees", "wrong-authority-key", "changed-record", "bad-statement", "bad-signature", "wrong-checkpoint-key", "truncated-journal", "trailing-journal", "wrong-tenant", "wrong-head", "missing-event", "outside-event", "missing-signer-files", "partial-signer-files", "public-journal", "symlink-journal", "byte-limit", "orphan-journal-flag", "orphan-signer-flag"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{"evidence.json": bytes.Clone(fixture.Evidence), "authority.key": []byte(fixture.GoKey), "journal.jsonl": bytes.Clone(fixture.Journal), "checkpoint.json": bytes.Clone(fixture.Statement), "signature.bin": bytes.Clone(fixture.Signature), "signer.pem": bytes.Clone(fixture.PublicKey)}
			switch scenario {
			case "wrong-authority-key":
				files["authority.key"] = []byte(fixture.GoKey + "wrong")
			case "changed-record":
				files["evidence.json"] = bytes.Replace(fixture.Evidence, []byte(`"repository":"owned"`), []byte(`"repository":"different"`), 1)
			case "bad-statement":
				files["checkpoint.json"] = append(files["checkpoint.json"], '\n')
			case "bad-signature":
				files["signature.bin"][0] ^= 1
			case "wrong-checkpoint-key":
				files["signer.pem"] = []byte("untrusted public input")
			case "truncated-journal":
				files["journal.jsonl"] = files["journal.jsonl"][:len(fixture.Journal)-1]
			case "trailing-journal":
				files["journal.jsonl"] = append(files["journal.jsonl"], []byte("{}\n")...)
			}
			for name, value := range files {
				if err := os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			journalPath := filepath.Join(dir, "journal.jsonl")
			if scenario == "public-journal" {
				if err := os.Chmod(journalPath, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink-journal" {
				link := journalPath + ".link"
				if err := os.Symlink(journalPath, link); err != nil {
					t.Fatal(err)
				}
				journalPath = link
			}
			args := []string{"--evidence-file", filepath.Join(dir, "evidence.json"), "--key-file", filepath.Join(dir, "authority.key"), "--journal-file", journalPath, "--journal-tenant", fixture.Head.Tenant, "--journal-event-sequence", "1", "--journal-through", "1", "--journal-through-hash", fixture.Head.Hash}
			flags := []string{"--checkpoint-file", filepath.Join(dir, "checkpoint.json"), "--checkpoint-signature-file", filepath.Join(dir, "signature.bin"), "--checkpoint-key-file", filepath.Join(dir, "signer.pem")}
			switch scenario {
			case "manual-and-journal":
				args = append(args, "--expected-sha256", crypt.Digest(fixture.Evidence))
			case "manual-disagrees":
				args = append(args, "--expected-sha256", strings.Repeat("f", 64))
			case "wrong-tenant":
				args[7] = "another-team"
			case "wrong-head":
				args[13] = strings.Repeat("c", 64)
			case "missing-event":
				args[9] = ""
			case "outside-event":
				args[9] = "2"
			case "missing-signer-files":
				flags = nil
			case "partial-signer-files":
				flags = flags[:2]
			case "byte-limit":
				args = append(args, "--journal-max-bytes", "1")
			case "orphan-journal-flag":
				args = append(args[:4], "--expected-sha256", crypt.Digest(fixture.Evidence), "--journal-tenant", fixture.Head.Tenant)
				flags = nil
			case "orphan-signer-flag":
				args = append(args[:4], "--expected-sha256", crypt.Digest(fixture.Evidence))
			}
			args = append(args, flags...)
			var out bytes.Buffer
			err := runGoChecksumVerify(args, &out)
			if scenario == "signed" || scenario == "manual-and-journal" {
				var result struct {
					Classification   string
					Digest           string                      `json:"evidence_sha256"`
					PackageAdmission bool                        `json:"package_admission"`
					Attribution      *checksumJournalAttribution `json:"journal_attribution"`
				}
				if err != nil || json.Unmarshal(out.Bytes(), &result) != nil || result.Classification != "fork" || result.Digest != crypt.Digest(fixture.Evidence) || result.PackageAdmission || result.Attribution == nil || !result.Attribution.CheckpointSignature.SignatureVerified || !result.Attribution.Journal.MatchesSuppliedCheckpoint || result.Attribution.EventSequence != 1 || result.Attribution.EventHash != fixture.Head.Hash || result.Attribution.Journal.ExportSHA256 != crypt.Digest(fixture.Journal) {
					t.Fatal("complete signed unit attribution missing", err, out.Len())
				}
				if bytes.Contains(out.Bytes(), []byte(fixture.GoKey)) || bytes.Contains(out.Bytes(), []byte(`"payload"`)) || bytes.Contains(out.Bytes(), []byte(`"repository"`)) || bytes.Contains(out.Bytes(), []byte(`"report"`)) {
					t.Fatal("private evidence contents leaked in receipt")
				}
			} else if err == nil || out.Len() != 0 {
				t.Fatal("unbound or incomplete journal emitted a partial receipt", scenario, err)
			}
		})
	}
}

func TestOfflineChecksumJournalKeepsSignedUnverifiedObservationNonzero(t *testing.T) {
	fixture := readChecksumJournalPublicFixture(t, "go-checksum-journal-unverified-public.json")
	dir := t.TempDir()
	for name, value := range map[string][]byte{"evidence.json": fixture.Evidence, "authority.key": []byte(fixture.GoKey), "journal.jsonl": fixture.Journal, "checkpoint.json": fixture.Statement, "signature.bin": fixture.Signature, "signer.pem": fixture.PublicKey} {
		if err := os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--evidence-file", filepath.Join(dir, "evidence.json"), "--key-file", filepath.Join(dir, "authority.key"), "--journal-file", filepath.Join(dir, "journal.jsonl"), "--journal-tenant", fixture.Head.Tenant, "--journal-event-sequence", "1", "--journal-through", "1", "--journal-through-hash", fixture.Head.Hash, "--checkpoint-file", filepath.Join(dir, "checkpoint.json"), "--checkpoint-signature-file", filepath.Join(dir, "signature.bin"), "--checkpoint-key-file", filepath.Join(dir, "signer.pem")}
	var out bytes.Buffer
	err := runGoChecksumVerify(args, &out)
	var result struct {
		Classification   string
		PackageAdmission bool                        `json:"package_admission"`
		Attribution      *checksumJournalAttribution `json:"journal_attribution"`
	}
	if err == nil || !strings.Contains(err.Error(), "remains unverified") || json.Unmarshal(out.Bytes(), &result) != nil || result.Classification != "unverified" || result.PackageAdmission || result.Attribution == nil || !result.Attribution.CheckpointSignature.SignatureVerified || !result.Attribution.Journal.MatchesSuppliedCheckpoint {
		t.Fatal("signed observation became fork or clean admission", err, out.Len())
	}
}
