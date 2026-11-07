// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestJournalSelectedReceiptRequiresSignedCompleteInputAndOmitsPayload(t *testing.T) {
	fixture := journalSignedCLI(t)
	for _, scenario := range []string{"signed", "missing-signer", "wrong-key", "wrong-signature", "truncated", "trailing", "selection-byte-limit", "selection-zero", "selection-oversize", "duplicate", "outside", "noncanonical", "negative", "broken-output"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{"journal": bytes.Clone(fixture.Export), "statement": bytes.Clone(fixture.Statement), "signature": bytes.Clone(fixture.Signature), "key": bytes.Clone(fixture.PublicKey)}
			switch scenario {
			case "wrong-key":
				files["key"] = []byte("untrusted public input")
			case "wrong-signature":
				files["signature"][0] ^= 1
			case "truncated":
				files["journal"] = files["journal"][:len(files["journal"])-1]
			case "trailing":
				files["journal"] = append(files["journal"], []byte("{}\n")...)
			}
			for name, raw := range files {
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--export-file", filepath.Join(dir, "journal"), "--tenant", fixture.Head.Tenant, "--through", strconv.FormatInt(fixture.Head.Sequence, 10), "--through-hash", fixture.Head.Hash, "--select-event", "1"}
			if scenario != "missing-signer" {
				args = append(args, "--checkpoint-file", filepath.Join(dir, "statement"), "--checkpoint-signature-file", filepath.Join(dir, "signature"), "--checkpoint-key-file", filepath.Join(dir, "key"))
			}
			switch scenario {
			case "selection-byte-limit":
				args = append(args, "--selection-bytes", "1")
			case "selection-zero":
				args = append(args, "--selection-bytes", "0")
			case "selection-oversize":
				args = append(args, "--selection-bytes", strconv.FormatInt(crypt.MaxJournalSelectionBytes+1, 10))
			case "duplicate":
				args = append(args, "--select-event", "1")
			case "outside":
				args = append(args, "--select-event", "2")
			case "noncanonical":
				args = append(args, "--select-event", "01")
			case "negative":
				args = append(args, "--select-event", "-1")
			}
			var out bytes.Buffer
			var writer io.Writer = &out
			if scenario == "broken-output" {
				writer = checksumBrokenWriter{}
			}
			err := runJournalVerify(args, writer)
			if scenario != "signed" {
				if err == nil || out.Len() != 0 {
					t.Fatal("invalid signed selection emitted receipt", scenario, err)
				}
				return
			}
			var receipt struct {
				crypt.JournalVerification
				CheckpointSignature *crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
				SelectedEvents      []map[string]json.RawMessage         `json:"selected_events"`
			}
			var page crypt.JournalPage
			if json.Unmarshal(bytes.TrimSpace(fixture.Export), &page) != nil {
				t.Fatal("owned public page")
			}
			event := page.Items[0]
			if err != nil || json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.CheckpointSignature == nil || !receipt.MatchesSuppliedCheckpoint || len(receipt.SelectedEvents) != 1 {
				t.Fatal("signed selection refused", err)
			}
			expected := journalEventSummary{Sequence: event.Sequence, Hash: event.Hash, PreviousHash: event.PreviousHash, PayloadBytes: len(event.Payload), PayloadSHA256: crypt.Digest([]byte(event.Payload))}
			var got journalEventSummary
			raw, _ := json.Marshal(receipt.SelectedEvents[0])
			if len(receipt.SelectedEvents[0]) != 5 || json.Unmarshal(raw, &got) != nil || got != expected || bytes.Contains(out.Bytes(), []byte(`"payload":`)) {
				t.Fatal("selected receipt changed identity or exposed original body")
			}
		})
	}
}

func TestJournalSelectionFlagCanonicalCountBound(t *testing.T) {
	for _, bad := range []string{"", "0", "-1", "01", "+1", " 1", "1 ", "9223372036854775808", strings.Repeat("1", 100)} {
		var fresh journalSequences
		if err := fresh.Set(bad); err == nil || len(fresh) != 0 {
			t.Fatal("noncanonical selector accepted or mutated list")
		}
	}
	var maximum journalSequences
	if err := maximum.Set("9223372036854775807"); err != nil || maximum.String() != "9223372036854775807" {
		t.Fatal("canonical int64 maximum refused")
	}
	if err := maximum.Set("9223372036854775807"); err == nil || len(maximum) != 1 {
		t.Fatal("duplicate mutated list below count limit")
	}
	var values journalSequences
	for n := 1; n <= crypt.MaxJournalSelectedEvents; n++ {
		if err := values.Set(strconv.Itoa(n)); err != nil {
			t.Fatal(err)
		}
	}
	before := append(journalSequences(nil), values...)
	if err := values.Set("257"); err == nil || !reflect.DeepEqual(values, before) {
		t.Fatal("overflow mutated bounded list")
	}
	if !strings.HasPrefix(values.String(), "1,2,") {
		t.Fatal("selector display changed")
	}
}
