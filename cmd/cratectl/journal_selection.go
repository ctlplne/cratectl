// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"strconv"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type journalSequences []int64

func (s *journalSequences) String() string {
	values := make([]string, 0, len(*s))
	for _, n := range *s {
		values = append(values, strconv.FormatInt(n, 10))
	}
	return strings.Join(values, ",")
}
func (s *journalSequences) Set(raw string) error {
	if len(raw) > 19 || len(*s) >= crypt.MaxJournalSelectedEvents {
		return errors.New("select-event exceeds its sequence/count budget")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != raw {
		return errors.New("select-event requires one canonical positive int64 sequence")
	}
	for _, selected := range *s {
		if selected == n {
			return errors.New("select-event sequences must be distinct")
		}
	}
	*s = append(*s, n)
	return nil
}

type journalEventSummary struct {
	Sequence      int64  `json:"sequence"`
	Hash          string `json:"hash"`
	PreviousHash  string `json:"previous_hash"`
	PayloadBytes  int    `json:"payload_bytes"`
	PayloadSHA256 string `json:"payload_sha256"`
}

func journalSummaries(events []crypt.JournalEvent) []journalEventSummary {
	out := make([]journalEventSummary, 0, len(events))
	for _, event := range events {
		out = append(out, journalEventSummary{event.Sequence, event.Hash, event.PreviousHash, len(event.Payload), crypt.Digest([]byte(event.Payload))})
	}
	return out
}
