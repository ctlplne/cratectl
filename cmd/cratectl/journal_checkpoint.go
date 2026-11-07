// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strconv"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type journalCheckpointFiles struct{ statement, signature, key *string }

func journalCheckpointFlags(f *flag.FlagSet) journalCheckpointFiles {
	return journalCheckpointFiles{
		f.String("checkpoint-file", "", "owner-private exact canonical checkpoint statement signed outside cratectl"),
		f.String("checkpoint-signature-file", "", "external raw 64-byte Ed25519 statement signature"),
		f.String("checkpoint-key-file", "", "independently trusted Ed25519 PUBLIC KEY PEM; never a signing private key"),
	}
}

func (files journalCheckpointFiles) verify(expected crypt.JournalAnchor) (*crypt.JournalCheckpointVerification, error) {
	if *files.statement == "" && *files.signature == "" && *files.key == "" {
		return nil, nil
	}
	if *files.statement == "" || *files.signature == "" || *files.key == "" {
		return nil, errors.New("supply all three checkpoint-file, checkpoint-signature-file and independently trusted checkpoint-key-file flags")
	}
	raw, err := configfile.ReadBytes(*files.statement, crypt.MaxJournalCheckpointStatement, true)
	if err != nil {
		return nil, errors.New("cannot read bounded private checkpoint statement")
	}
	defer clear(raw)
	signature, err := configfile.ReadBytes(*files.signature, crypt.JournalCheckpointSignatureBytes, false)
	if err != nil {
		return nil, errors.New("cannot read exact external checkpoint signature")
	}
	key, err := configfile.ReadBytes(*files.key, crypt.MaxJournalCheckpointPublicKey, false)
	if err != nil {
		return nil, errors.New("cannot read bounded independently trusted public checkpoint key")
	}
	defer clear(key)
	verified, err := crypt.VerifyJournalCheckpoint(raw, signature, key, expected)
	if err != nil {
		return nil, errors.New("external checkpoint signature did not verify with the supplied public key and exact tenant/terminal binding; no journal attribution was established")
	}
	return &verified, nil
}

func writeJournalReceipt(out io.Writer, receipt crypt.JournalVerification, signature *crypt.JournalCheckpointVerification, selected ...journalEventSummary) error {
	trust := "Attribution depends on how the supplied checkpoint was authenticated outside this export; matching hashes do not prove event claims or approve package bytes."
	if signature != nil {
		trust = "The checkpoint signature verifies under the separately supplied public key. Attribution depends on independent trust in that key; this does not prove latest history, event claims, external delivery or package approval."
	}
	return json.NewEncoder(out).Encode(struct {
		crypt.JournalVerification
		CheckpointSignature *crypt.JournalCheckpointVerification `json:"checkpoint_signature,omitempty"`
		Trust               string                               `json:"trust"`
		SelectedEvents      []journalEventSummary                `json:"selected_events,omitempty"`
	}{receipt, signature, trust, selected})
}

// Prepare a bounded unsigned statement for the customer's external signer.
// This command never accepts a signing key or invokes a signing operation.
func runJournalCheckpoint(args []string, out io.Writer) error {
	f := flag.NewFlagSet("journal-checkpoint", flag.ContinueOnError)
	tenant := f.String("tenant", "", "tenant whose exact observed head will be signed externally")
	through := f.String("through", "", "exact observed terminal sequence")
	hash := f.String("through-hash", "", "exact observed lowercase terminal SHA-256; empty at genesis")
	if err := f.Parse(args); err != nil {
		return err
	}
	sequence, err := strconv.ParseInt(*through, 10, 64)
	anchor := crypt.JournalAnchor{Tenant: *tenant, Sequence: sequence, Hash: *hash}
	if f.NArg() != 0 || err != nil || strconv.FormatInt(sequence, 10) != *through || !anchor.Valid() {
		return errors.New("supply tenant and exact canonical terminal sequence/hash; genesis is sequence zero and an empty hash")
	}
	raw, err := crypt.JournalCheckpointBytes(anchor)
	if err != nil {
		return err
	}
	n, err := out.Write(raw)
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}
