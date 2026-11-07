// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
)

type selectionCountingReader struct {
	io.Reader
	bytes int
}

func (r *selectionCountingReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.bytes += n
	return n, e
}

func TestJournalMultipleSelectionsRequireWholeRangeAndBoundRetainedPayload(t *testing.T) {
	start, head, pages := journalFixture(t)
	original := journalBytes(t, pages)
	retained := int64(len(pages[0].Items[0].Payload) + len(pages[1].Items[0].Payload))
	for _, scenario := range []string{"ordered", "reverse", "single", "empty", "duplicate", "before", "after", "count", "selection-zero", "selection-too-large", "selection-one-short", "input-short", "tail-missing", "tail-corrupt", "trailing", "reader-error", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			raw := bytes.Clone(original)
			sequences := []int64{1, 2}
			selectedBytes := retained
			budget := int64(len(raw))
			ctx := context.Background()
			var want error = ErrJournalEvidence
			valid := scenario == "ordered" || scenario == "reverse" || scenario == "single"
			switch scenario {
			case "reverse":
				sequences = []int64{2, 1}
			case "single":
				sequences = []int64{2}
			case "empty":
				sequences = nil
				want = ErrJournalLimit
			case "duplicate":
				sequences = []int64{1, 1}
			case "before":
				sequences = []int64{0, 1}
			case "after":
				sequences = []int64{1, 3}
			case "count":
				sequences = make([]int64, MaxJournalSelectedEvents+1)
				want = ErrJournalLimit
			case "selection-zero":
				selectedBytes = 0
				want = ErrJournalLimit
			case "selection-too-large":
				selectedBytes = MaxJournalSelectionBytes + 1
				want = ErrJournalLimit
			case "selection-one-short":
				selectedBytes--
				want = ErrJournalLimit
			case "input-short":
				budget--
				want = ErrJournalLimit
			case "tail-missing":
				raw = journalBytes(t, pages[:1])
			case "tail-corrupt":
				raw = bytes.Replace(raw, []byte(pages[1].Items[0].Hash), []byte(pages[0].Items[0].Hash), 1)
			case "trailing":
				raw = append(raw, []byte("{}\n")...)
				budget = int64(len(raw))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "reader-error":
				want = io.ErrUnexpectedEOF
			}
			var reader io.Reader = bytes.NewReader(raw)
			if scenario == "reader-error" {
				reader = failedJournalReader{reader}
			}
			counted := &selectionCountingReader{Reader: reader}
			receipt, events, err := VerifyJournalExportEvents(ctx, counted, start, head, budget, sequences, selectedBytes)
			if valid {
				if err != nil || !receipt.MatchesSuppliedCheckpoint || receipt.ExportSHA256 != Digest(raw) || len(events) != len(sequences) || counted.bytes != len(raw) {
					t.Fatal("complete one-pass selection failed", err)
				}
				for n, event := range events {
					if event != pages[sequences[n]-1].Items[0] {
						t.Fatal("original event/order changed")
					}
				}
			} else if !errors.Is(err, want) || events != nil || !reflect.DeepEqual(receipt, JournalVerification{}) {
				t.Fatal("failed range leaked selections or receipt", scenario, err)
			}
			if scenario == "empty" || scenario == "duplicate" || scenario == "before" || scenario == "after" || scenario == "count" || scenario == "selection-zero" || scenario == "selection-too-large" {
				if counted.bytes != 0 {
					t.Fatal("invalid selection consumed input")
				}
			}
		})
	}
}

func TestJournalMultipleSelectionExactCountAndSingleSelectorCompatibility(t *testing.T) {
	start := JournalAnchor{Tenant: "journal-team"}
	items := make([]JournalEvent, 0, MaxJournalSelectedEvents)
	sequences := make([]int64, 0, MaxJournalSelectedEvents)
	var selectedBytes int64
	for n := int64(1); n <= MaxJournalSelectedEvents; n++ {
		raw, _ := json.Marshal(map[string]any{"tenant": start.Tenant, "sequence": n, "kind": "owned.fixture", "data": "inert"})
		previous := ""
		if len(items) > 0 {
			previous = items[len(items)-1].Hash
		}
		items = append(items, JournalEvent{n, string(raw), previous, Digest([]byte(previous + "\n" + string(raw)))})
		sequences = append(sequences, n)
		selectedBytes += int64(len(raw))
	}
	head := JournalAnchor{Tenant: start.Tenant, Sequence: MaxJournalSelectedEvents, Hash: items[len(items)-1].Hash}
	raw := journalBytes(t, []JournalPage{{Version: 1, Tenant: start.Tenant, Through: head.Sequence, ThroughHash: head.Hash, Items: items, NextAfter: head.Sequence, NextHash: head.Hash}})
	receipt, events, err := VerifyJournalExportEvents(context.Background(), bytes.NewReader(raw), start, head, int64(len(raw)), sequences, selectedBytes)
	if err != nil || !reflect.DeepEqual(events, items) || receipt.Events != MaxJournalSelectedEvents {
		t.Fatal("exact selection count/byte bound refused", err)
	}
	oldReceipt, one, err := VerifyJournalExportEvent(context.Background(), bytes.NewReader(raw), start, head, int64(len(raw)), head.Sequence)
	if err != nil || one != items[len(items)-1] || oldReceipt != receipt {
		t.Fatal("single-selector compatibility changed", err)
	}
}

func FuzzJournalMultipleSelectionsDiscardIncompleteInput(f *testing.F) {
	start, head, pages := journalFixture(f)
	f.Add(journalBytes(f, pages), int64(1), int64(2), int64(4096))
	f.Add(journalBytes(f, pages[:1]), int64(2), int64(1), int64(4096))
	f.Fuzz(func(t *testing.T, raw []byte, a, b, budget int64) {
		if len(raw) > 64<<10 {
			return
		}
		receipt, events, err := VerifyJournalExportEvents(context.Background(), bytes.NewReader(raw), start, head, 64<<10, []int64{a, b}, budget)
		if err != nil {
			if events != nil || !reflect.DeepEqual(receipt, JournalVerification{}) {
				t.Fatal("failed selection leaked data")
			}
			return
		}
		if a == b || len(events) != 2 || events[0].Sequence != a || events[1].Sequence != b || receipt.ExportSHA256 != Digest(raw) || !receipt.MatchesSuppliedCheckpoint {
			t.Fatal("unbound selection")
		}
		var size int64
		for _, e := range events {
			if VerifyJournalEvent(start.Tenant, e) != nil {
				t.Fatal("invalid selected event")
			}
			size += int64(len(e.Payload))
		}
		if size > budget {
			t.Fatal("retained payload budget bypass")
		}
	})
}
