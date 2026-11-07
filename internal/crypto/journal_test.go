// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func journalFixture(t testing.TB) (JournalAnchor, JournalAnchor, []JournalPage) {
	t.Helper()
	start := JournalAnchor{Tenant: "journal-team"}
	previous := ""
	events := []JournalEvent{}
	for n := int64(1); n <= 2; n++ {
		payload, err := json.Marshal(map[string]any{"tenant": start.Tenant, "sequence": n, "actor": "operator", "kind": "owned.fixture", "data": map[string]string{"claim": "not independently observed"}})
		if err != nil {
			t.Fatal(err)
		}
		event := JournalEvent{Sequence: n, Payload: string(payload), PreviousHash: previous, Hash: Digest([]byte(previous + "\n" + string(payload)))}
		events = append(events, event)
		previous = event.Hash
	}
	head := JournalAnchor{Tenant: start.Tenant, Sequence: 2, Hash: previous}
	return start, head, []JournalPage{
		{Version: 1, Tenant: start.Tenant, Through: 2, ThroughHash: head.Hash, Items: events[:1], More: true, NextAfter: 1, NextHash: events[0].Hash},
		{Version: 1, Tenant: start.Tenant, After: 1, AfterHash: events[0].Hash, Through: 2, ThroughHash: head.Hash, Items: events[1:], NextAfter: 2, NextHash: head.Hash},
	}
}

func journalBytes(t testing.TB, pages []JournalPage) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, page := range pages {
		if err := json.NewEncoder(&out).Encode(page); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func TestJournalExportRequiresEveryPageAndSeparatelySuppliedTerminalBinding(t *testing.T) {
	start, head, pages := journalFixture(t)
	for _, scenario := range []string{"complete", "one-blank-between-pages", "partial-start", "empty-genesis", "missing-page", "missing-final-newline", "duplicate", "reordered", "trailing-page", "wrong-head", "wrong-tenant", "wrong-start", "empty-input", "input-byte-limit", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			begin, end := start, head
			input := journalBytes(t, pages)
			ctx := context.Background()
			budget := int64(len(input))
			var want error = ErrJournalEvidence
			valid := false
			switch scenario {
			case "complete":
				valid = true
			case "one-blank-between-pages":
				input = bytes.ReplaceAll(input, []byte("\n"), []byte("\n\n"))
				budget = int64(len(input))
				valid = true
			case "partial-start":
				begin = JournalAnchor{Tenant: start.Tenant, Sequence: 1, Hash: pages[0].NextHash}
				input = journalBytes(t, pages[1:])
				valid = true
			case "empty-genesis":
				end = begin
				input = journalBytes(t, []JournalPage{{Version: 1, Tenant: start.Tenant, Items: []JournalEvent{}}})
				valid = true
			case "missing-page":
				input = journalBytes(t, pages[:1])
			case "missing-final-newline":
				input = input[:len(input)-1]
			case "duplicate":
				input = journalBytes(t, []JournalPage{pages[0], pages[0], pages[1]})
				budget = int64(len(input))
			case "reordered":
				input = journalBytes(t, []JournalPage{pages[1], pages[0]})
			case "trailing-page":
				input = append(input, journalBytes(t, pages[1:])...)
				budget = int64(len(input))
			case "wrong-head":
				end.Hash = strings.Repeat("0", 64)
			case "wrong-tenant":
				end.Tenant = "another-team"
			case "wrong-start":
				begin.Sequence, begin.Hash = 1, pages[0].NextHash
			case "empty-input":
				input = nil
			case "input-byte-limit":
				budget--
				want = ErrJournalLimit
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
				want = context.Canceled
			}
			receipt, err := VerifyJournalExport(ctx, bytes.NewReader(input), begin, end, budget)
			if valid {
				if err != nil || !receipt.MatchesSuppliedCheckpoint || receipt.HeadHash != end.Hash || receipt.HeadSequence != end.Sequence || receipt.Events != end.Sequence-begin.Sequence || receipt.ExportSHA256 != Digest(input) {
					t.Fatal("complete separately bound journal range refused", err, receipt)
				}
			} else if !errors.Is(err, want) || !reflect.DeepEqual(receipt, JournalVerification{}) {
				t.Fatal("invalid range returned a partial success receipt", err, receipt)
			}
		})
	}
}

func TestJournalOriginalPayloadIdentityAndLinkCannotBeReconstructedOrRelabelled(t *testing.T) {
	start, _, pages := journalFixture(t)
	for _, scenario := range []string{"original", "tenant", "sequence", "previous-link", "raw-payload", "digest", "case-alias", "duplicate", "invalid-utf8", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			event := pages[0].Items[0]
			switch scenario {
			case "tenant":
				event.Payload = strings.Replace(event.Payload, "journal-team", "another-team", 1)
			case "sequence":
				event.Payload = strings.Replace(event.Payload, `"sequence":1`, `"sequence":2`, 1)
			case "previous-link":
				event.PreviousHash = "invalid"
			case "raw-payload":
				event.Payload += " "
			case "digest":
				event.Hash = strings.Repeat("0", 64)
			case "case-alias":
				event.Payload = strings.Replace(event.Payload, `"tenant":`, `"Tenant":`, 1)
			case "duplicate":
				event.Payload = `{"tenant":"another-team",` + event.Payload[1:]
			case "invalid-utf8":
				event.Payload = string([]byte{0xff})
			case "oversized":
				event.Payload = strings.Repeat("x", MaxJournalPayload+1)
			}
			if scenario == "tenant" || scenario == "sequence" || scenario == "case-alias" || scenario == "duplicate" || scenario == "invalid-utf8" {
				event.Hash = Digest([]byte(event.PreviousHash + "\n" + event.Payload))
			}
			err := VerifyJournalEvent(start.Tenant, event)
			if scenario == "original" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unbound or altered original event accepted", scenario)
			}
		})
	}
}

func TestJournalPageDecoderBoundsArraysAndRejectsAmbiguousWireFields(t *testing.T) {
	_, _, pages := journalFixture(t)
	raw, _ := json.Marshal(pages[0])
	if _, err := DecodeJournalPage(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append([]byte(`{"version":1,`), raw[1:]...),
		bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1),
		bytes.Replace(raw, []byte(`"more":true`), []byte(`"more":null`), 1),
		append(append([]byte{}, raw...), []byte(` {}`)...),
		append([]byte(" "), raw...),
		[]byte("null"), []byte{0xff},
	} {
		if _, err := DecodeJournalPage(bad); err == nil {
			t.Fatal("ambiguous page accepted")
		}
	}
	large := pages[0]
	large.Items = make([]JournalEvent, MaxJournalPageEvents+1)
	for n := range large.Items {
		large.Items[n] = pages[0].Items[0]
	}
	raw, _ = json.Marshal(large)
	if _, err := DecodeJournalPage(raw); !errors.Is(err, ErrJournalLimit) {
		t.Fatal("unbounded event array allocated", err)
	}
	if _, err := DecodeJournalPage(bytes.Repeat([]byte{' '}, MaxJournalPageBytes)); !errors.Is(err, ErrJournalLimit) {
		t.Fatal(err)
	}
}

type failedJournalReader struct{ reader io.Reader }

func (r failedJournalReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func TestJournalReaderFailureCannotProduceAnAuthenticatedReceipt(t *testing.T) {
	start, head, pages := journalFixture(t)
	raw := journalBytes(t, pages)
	out, err := VerifyJournalExport(context.Background(), failedJournalReader{bytes.NewReader(raw)}, start, head, int64(len(raw))+1)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !reflect.DeepEqual(out, JournalVerification{}) {
		t.Fatal("reader failure produced success", err, out)
	}
}

func FuzzJournalPageBindings(f *testing.F) {
	start, head, pages := journalFixture(f)
	valid, _ := json.Marshal(pages[0])
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		page, err := DecodeJournalPage(raw)
		if err != nil {
			return
		}
		next, err := VerifyJournalPage(context.Background(), page, start, head)
		if err != nil {
			return
		}
		canonical, _ := json.Marshal(page)
		if !bytes.Equal(raw, canonical) || next.Sequence <= start.Sequence || next.Sequence > head.Sequence || next.Tenant != start.Tenant || len(page.Items) > MaxJournalPageEvents {
			t.Fatal("unbounded or unbound page accepted")
		}
	})
}
