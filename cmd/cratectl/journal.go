// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strconv"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

// Offline verification needs a separately authenticated terminal checkpoint.
// This command never asks the same untrusted export to supply its own trust.
func runJournalVerify(args []string, out io.Writer) error {
	f := flag.NewFlagSet("journal-verify", flag.ContinueOnError)
	checkpointFiles := journalCheckpointFlags(f)
	file := f.String("export-file", "", "owner-private canonical journal JSONL export")
	tenant := f.String("tenant", "", "tenant from the separately trusted checkpoint")
	after := f.String("after", "0", "exact start sequence, or zero for genesis")
	afterHash := f.String("after-hash", "", "separately trusted start SHA-256; empty at genesis")
	through := f.String("through", "", "exact terminal sequence from a separately trusted record or external signature")
	throughHash := f.String("through-hash", "", "separately authenticated terminal SHA-256; empty only at genesis")
	budget := f.Int64("max-bytes", 1<<30, "maximum export input bytes, 1–68719476736")
	timeout := f.Duration("timeout", 5*time.Minute, "bounded offline verification time, greater than zero and at most 1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	startSequence, a := strconv.ParseInt(*after, 10, 64)
	headSequence, h := strconv.ParseInt(*through, 10, 64)
	start := crypt.JournalAnchor{Tenant: *tenant, Sequence: startSequence, Hash: *afterHash}
	head := crypt.JournalAnchor{Tenant: *tenant, Sequence: headSequence, Hash: *throughHash}
	if f.NArg() != 0 || *file == "" || a != nil || h != nil || strconv.FormatInt(startSequence, 10) != *after || strconv.FormatInt(headSequence, 10) != *through || !start.Valid() || !head.Valid() || startSequence > headSequence || *budget < 1 || *budget > crypt.MaxJournalInputBytes || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply export-file, tenant and canonical after/through sequences with exact separately trusted hashes; keep max-bytes within 1–64 GiB and timeout within 1h")
	}
	signature, err := checkpointFiles.verify(head)
	if err != nil {
		return err
	}
	input, err := configfile.OpenBounded(*file, *budget, true)
	if err != nil {
		return errors.New("cannot open bounded private journal export; use a regular owner-private file within max-bytes")
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := crypt.VerifyJournalExport(ctx, input, start, head, *budget)
	if err != nil {
		return errors.New("journal export did not completely verify; preserve it and inspect the supplied tenant, checkpoints, page continuity and resource limits")
	}
	return writeJournalReceipt(out, receipt, signature)
}
