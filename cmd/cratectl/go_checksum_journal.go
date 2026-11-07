// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"flag"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type checksumJournalFlags struct {
	file, tenant, event, after, afterHash, through, throughHash *string
	maxBytes                                                    *int64
	timeout                                                     *time.Duration
	checkpoint                                                  journalCheckpointFiles
}

func checksumJournalArguments(f *flag.FlagSet) checksumJournalFlags {
	return checksumJournalFlags{
		file:        f.String("journal-file", "", "private complete journal JSONL for automatic failure digest attribution"),
		tenant:      f.String("journal-tenant", "", "exact independently selected tenant"),
		event:       f.String("journal-event-sequence", "", "exact original typed failure event sequence"),
		after:       f.String("journal-after", "0", "trusted prior sequence, zero for genesis"),
		afterHash:   f.String("journal-after-hash", "", "trusted start hash, empty at genesis"),
		through:     f.String("journal-through", "", "exact independently selected terminal sequence"),
		throughHash: f.String("journal-through-hash", "", "exact terminal SHA-256 authenticated by the external checkpoint signature"),
		maxBytes:    f.Int64("journal-max-bytes", 1<<30, "journal input byte budget, 1–68719476736"),
		timeout:     f.Duration("journal-timeout", 5*time.Minute, "complete journal verification timeout, positive through 1h"),
		checkpoint:  journalCheckpointFlags(f),
	}
}

type checksumJournalAttribution struct {
	Journal             crypt.JournalVerification           `json:"journal"`
	EventSequence       int64                               `json:"event_sequence"`
	EventHash           string                              `json:"event_hash"`
	CheckpointSignature crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
}

func (j checksumJournalFlags) selectEvent(f *flag.FlagSet) (*checksumJournalAttribution, crypt.JournalEvent, error) {
	if *j.file == "" {
		supplied := false
		f.Visit(func(v *flag.Flag) {
			if strings.HasPrefix(v.Name, "journal-") || strings.HasPrefix(v.Name, "checkpoint-") {
				supplied = true
			}
		})
		if supplied {
			return nil, crypt.JournalEvent{}, errors.New("journal attribution flags require journal-file and all external checkpoint signature inputs")
		}
		return nil, crypt.JournalEvent{}, nil
	}
	parse := func(value string) (int64, bool) {
		n, err := strconv.ParseInt(value, 10, 64)
		return n, err == nil && n >= 0 && strconv.FormatInt(n, 10) == value
	}
	a, aok := parse(*j.after)
	h, hok := parse(*j.through)
	sequence, sok := parse(*j.event)
	start := crypt.JournalAnchor{Tenant: *j.tenant, Sequence: a, Hash: *j.afterHash}
	head := crypt.JournalAnchor{Tenant: *j.tenant, Sequence: h, Hash: *j.throughHash}
	if !aok || !hok || !sok || !start.Valid() || !head.Valid() || a > h || sequence <= a || sequence > h || *j.maxBytes < 1 || *j.maxBytes > crypt.MaxJournalInputBytes || *j.timeout <= 0 || *j.timeout > time.Hour {
		return nil, crypt.JournalEvent{}, errors.New("supply exact journal tenant/start/head/event bindings and bounded input/time budgets")
	}
	signature, err := j.checkpoint.verify(head)
	if err != nil {
		return nil, crypt.JournalEvent{}, err
	}
	if signature == nil {
		return nil, crypt.JournalEvent{}, errors.New("automatic journal attribution requires checkpoint-file, checkpoint-signature-file and an independently trusted checkpoint-key-file")
	}
	input, err := configfile.OpenBounded(*j.file, *j.maxBytes, true)
	if err != nil {
		return nil, crypt.JournalEvent{}, errors.New("cannot open bounded private complete journal file")
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *j.timeout)
	defer cancel()
	receipt, event, err := crypt.VerifyJournalExportEvent(ctx, input, start, head, *j.maxBytes, sequence)
	if err != nil {
		return nil, crypt.JournalEvent{}, errors.New("complete signed journal range and selected original event did not verify; no failure attribution was established")
	}
	return &checksumJournalAttribution{receipt, event.Sequence, event.Hash, *signature}, event, nil
}
