// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"regexp"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

var checksumEvidenceDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// This subcommand is entirely offline. It consumes separately supplied trust
// and identity, never the verifier key embedded in an untrusted download alone.
func runGoChecksumVerify(args []string, out io.Writer) error {
	f := flag.NewFlagSet("go-checksum-verify", flag.ContinueOnError)
	journal := checksumJournalArguments(f)
	evidence := f.String("evidence-file", "", "exact downloaded failure JSON, at most 2 MiB")
	keyFile := f.String("key-file", "", "separately trusted public checksum verifier key")
	digest := f.String("expected-sha256", "", "exact evidence SHA-256 from a separately trusted journal or export manifest")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *evidence == "" || *keyFile == "" || *digest != "" && !checksumEvidenceDigest.MatchString(*digest) || *digest == "" && *journal.file == "" {
		return errors.New("supply evidence-file, a separately trusted key-file and expected-sha256 or a complete externally signed journal attribution")
	}
	attribution, event, err := journal.selectEvent(f)
	if err != nil {
		return err
	}
	raw, err := configfile.ReadBytes(*evidence, store.MaxGoChecksumFailureEvidence, true)
	if err != nil {
		return errors.New("cannot read bounded private evidence; use a regular owner-private file of at most 2 MiB")
	}
	defer clear(raw)
	if *digest != "" && crypt.Digest(raw) != *digest {
		return errors.New("evidence bytes do not match the separately supplied SHA-256")
	}
	key, err := configfile.ReadBytes(*keyFile, 4097, false)
	if err != nil {
		return errors.New("cannot read bounded public verifier key; use a regular key file of at most 4097 bytes")
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	record, err := store.VerifyGoChecksumFailureEvidence(ctx, raw, strings.TrimSpace(string(key)))
	if err != nil {
		return errors.New("failure evidence did not verify under the separately supplied key; inspect its exact digest, canonical encoding and original observations")
	}
	attributionText := "depends on the separately trusted journal or manifest supplying this digest"
	if attribution != nil {
		bound, err := store.BindGoChecksumFailureJournalEvent(raw, record, event)
		if err != nil || *digest != "" && bound != *digest {
			return errors.New("failure evidence is not bound to the exact selected original journal event")
		}
		*digest = bound
		attributionText = "bound to the exact original event in a complete externally signed journal range; attribution depends on independent trust in the checkpoint signer and checksum authority, and does not prove event truth or package admission"
	}
	result := struct {
		Classification     string                      `json:"classification"`
		EvidenceSHA256     string                      `json:"evidence_sha256"`
		KeyDigest          string                      `json:"key_digest"`
		DigestMatched      bool                        `json:"supplied_digest_matched"`
		Attribution        string                      `json:"attribution"`
		PackageAdmission   bool                        `json:"package_admission"`
		JournalAttribution *checksumJournalAttribution `json:"journal_attribution,omitempty"`
	}{record.Classification, *digest, record.KeyDigest, true, attributionText, false, attribution}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return err
	}
	if record.Classification != "fork" {
		return errors.New("the retained observation remains unverified; it does not authenticate a checksum authority fork or approve package bytes")
	}
	return nil
}
