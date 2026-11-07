// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"unicode/utf8"
)

const MaxJournalPayload = 256 << 10
const MaxJournalPageBytes = 2 << 20
const MaxJournalPageEvents = 1000
const MaxJournalFrames = 65536
const MaxJournalInputBytes int64 = 64 << 30

var ErrJournalEvidence = errors.New("journal range does not match its original links and supplied checkpoint")
var ErrJournalLimit = errors.New("journal range exceeds its supported verification budget")
var journalTenant = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var journalDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// An anchor must be authenticated outside this document. A server response
// containing its own hash does not authenticate itself.
type JournalAnchor struct {
	Tenant   string `json:"tenant"`
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

func (a JournalAnchor) Valid() bool {
	return journalTenant.MatchString(a.Tenant) && a.Sequence >= 0 && (a.Sequence == 0 && a.Hash == "" || a.Sequence > 0 && journalDigest.MatchString(a.Hash))
}

type JournalEvent struct {
	Sequence     int64  `json:"sequence"`
	Payload      string `json:"payload"`
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
}

type JournalPage struct {
	Version     int            `json:"version"`
	Tenant      string         `json:"tenant"`
	After       int64          `json:"after"`
	AfterHash   string         `json:"after_hash"`
	Through     int64          `json:"through"`
	ThroughHash string         `json:"through_hash"`
	Items       []JournalEvent `json:"items"`
	More        bool           `json:"more"`
	NextAfter   int64          `json:"next_after"`
	NextHash    string         `json:"next_hash"`
}

// Parse an object's keys case-sensitively, rejecting duplicates before decoding
// typed fields. Caller-provided byte bounds also bound retained RawMessages.
func journalObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrJournalEvidence
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || len(name) > 128 || len(fields) >= 64 {
			return nil, ErrJournalEvidence
		}
		if _, exists := fields[name]; exists {
			return nil, ErrJournalEvidence
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrJournalEvidence
		}
		fields[name] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrJournalEvidence
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return nil, ErrJournalEvidence
	}
	return fields, nil
}

// Verify exactly the retained payload bytes, never a reconstructed old event.
// This checks a local link; only a separately authenticated terminal anchor can
// establish attribution of the complete supplied range.
func VerifyJournalEvent(tenant string, event JournalEvent) error {
	if len(event.Payload) > MaxJournalPayload {
		return ErrJournalLimit
	}
	if !journalTenant.MatchString(tenant) || event.Sequence <= 0 || !utf8.ValidString(event.Payload) || !journalDigest.MatchString(event.Hash) || event.PreviousHash != "" && !journalDigest.MatchString(event.PreviousHash) || Digest([]byte(event.PreviousHash+"\n"+event.Payload)) != event.Hash {
		return ErrJournalEvidence
	}
	fields, err := journalObject([]byte(event.Payload))
	var payloadTenant string
	var sequence int64
	if err != nil || json.Unmarshal(fields["tenant"], &payloadTenant) != nil || json.Unmarshal(fields["sequence"], &sequence) != nil || payloadTenant != tenant || sequence != event.Sequence {
		return ErrJournalEvidence
	}
	return nil
}

func VerifyJournalPage(ctx context.Context, page JournalPage, start, head JournalAnchor) (JournalAnchor, error) {
	if err := ctx.Err(); err != nil {
		return JournalAnchor{}, err
	}
	if !start.Valid() || !head.Valid() || start.Tenant != head.Tenant || start.Sequence > head.Sequence || page.Version != 1 || page.Tenant != start.Tenant || page.After != start.Sequence || page.AfterHash != start.Hash || page.Through != head.Sequence || page.ThroughHash != head.Hash || page.Items == nil || len(page.Items) > MaxJournalPageEvents {
		return JournalAnchor{}, ErrJournalEvidence
	}
	current := start
	for _, event := range page.Items {
		if err := ctx.Err(); err != nil {
			return JournalAnchor{}, err
		}
		if current.Sequence >= head.Sequence || event.Sequence != current.Sequence+1 || event.PreviousHash != current.Hash {
			return JournalAnchor{}, ErrJournalEvidence
		}
		if err := VerifyJournalEvent(start.Tenant, event); err != nil {
			return JournalAnchor{}, err
		}
		current = JournalAnchor{Tenant: start.Tenant, Sequence: event.Sequence, Hash: event.Hash}
	}
	if page.NextAfter != current.Sequence || page.NextHash != current.Hash || page.More != (current.Sequence < head.Sequence) || page.More && len(page.Items) == 0 || !page.More && current.Hash != head.Hash {
		return JournalAnchor{}, ErrJournalEvidence
	}
	encoded, err := json.Marshal(page)
	if err != nil || len(encoded)+1 > MaxJournalPageBytes {
		return JournalAnchor{}, ErrJournalLimit
	}
	return current, nil
}

func DecodeJournalPage(raw []byte) (JournalPage, error) {
	var page JournalPage
	if len(raw)+1 > MaxJournalPageBytes {
		return page, ErrJournalLimit
	}
	if !utf8.Valid(raw) {
		return page, ErrJournalEvidence
	}
	fields, err := journalObject(raw)
	if err != nil || len(fields) != 10 {
		return page, ErrJournalEvidence
	}
	for _, name := range []string{"version", "tenant", "after", "after_hash", "through", "through_hash", "items", "more", "next_after", "next_hash"} {
		if value, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return page, ErrJournalEvidence
		}
	}
	// Decode at most one bounded event at a time, refusing the 1,001st before
	// allocating its fields. Do not unmarshal an attacker-sized slice first.
	d := json.NewDecoder(bytes.NewReader(fields["items"]))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return page, ErrJournalEvidence
	}
	page.Items = []JournalEvent{}
	for d.More() {
		if len(page.Items) >= MaxJournalPageEvents {
			return JournalPage{}, ErrJournalLimit
		}
		var event JournalEvent
		var rawEvent json.RawMessage
		if d.Decode(&rawEvent) != nil || json.Unmarshal(rawEvent, &event) != nil {
			return JournalPage{}, ErrJournalEvidence
		}
		canonical, err := json.Marshal(event)
		if err != nil || !bytes.Equal(rawEvent, canonical) {
			return JournalPage{}, ErrJournalEvidence
		}
		if len(event.Payload) > MaxJournalPayload {
			return JournalPage{}, ErrJournalLimit
		}
		page.Items = append(page.Items, event)
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') {
		return JournalPage{}, ErrJournalEvidence
	}
	// Populate scalar fields separately, preserving the bounded item slice.
	delete(fields, "items")
	scalars, err := json.Marshal(fields)
	if err != nil || json.Unmarshal(scalars, &page) != nil {
		return JournalPage{}, ErrJournalEvidence
	}
	canonical, err := json.Marshal(page)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalPage{}, ErrJournalEvidence
	}
	return page, nil
}

type JournalVerification struct {
	Tenant                    string `json:"tenant"`
	StartSequence             int64  `json:"start_sequence"`
	StartHash                 string `json:"start_hash"`
	HeadSequence              int64  `json:"head_sequence"`
	HeadHash                  string `json:"head_hash"`
	Pages                     int    `json:"pages"`
	Events                    int64  `json:"events"`
	ExportSHA256              string `json:"export_sha256"`
	MatchesSuppliedCheckpoint bool   `json:"matches_supplied_checkpoint"`
}

// Stream canonical JSON page records, with an optional blank line between
// records for the management CLI's normal terminal newline. No success receipt
// is returned until all input and the supplied terminal anchor are verified.
func VerifyJournalExport(ctx context.Context, input io.Reader, start, head JournalAnchor, maxBytes int64) (JournalVerification, error) {
	return verifyJournalExport(ctx, input, start, head, maxBytes, nil)
}

type journalSelection struct {
	sequence int64
	event    JournalEvent
}

// Select one original event while verifying the complete immutable range. The
// selection is never returned to a caller if any later page or EOF fails.
func VerifyJournalExportEvent(ctx context.Context, input io.Reader, start, head JournalAnchor, maxBytes int64, sequence int64) (JournalVerification, JournalEvent, error) {
	if sequence <= start.Sequence || sequence > head.Sequence {
		return JournalVerification{}, JournalEvent{}, ErrJournalEvidence
	}
	selection := journalSelection{sequence: sequence}
	receipt, err := verifyJournalExport(ctx, input, start, head, maxBytes, &selection)
	if err != nil {
		return JournalVerification{}, JournalEvent{}, err
	}
	if selection.event.Sequence != sequence {
		return JournalVerification{}, JournalEvent{}, ErrJournalEvidence
	}
	return receipt, selection.event, nil
}

func verifyJournalExport(ctx context.Context, input io.Reader, start, head JournalAnchor, maxBytes int64, selection *journalSelection) (JournalVerification, error) {
	if input == nil || !start.Valid() || !head.Valid() || start.Tenant != head.Tenant || start.Sequence > head.Sequence || maxBytes < 1 || maxBytes > MaxJournalInputBytes {
		return JournalVerification{}, ErrJournalEvidence
	}
	hasher := SHA256()
	limited := &io.LimitedReader{R: io.TeeReader(input, hasher), N: maxBytes + 1}
	r := bufio.NewReaderSize(limited, 64<<10)
	current := start
	pages, frames := 0, 0
	var events int64
	complete := false
	blank := false
	for {
		if err := ctx.Err(); err != nil {
			return JournalVerification{}, err
		}
		var frame []byte
		for {
			fragment, err := r.ReadSlice('\n')
			if maxBytes+1-limited.N > maxBytes || len(frame)+len(fragment) > MaxJournalPageBytes {
				return JournalVerification{}, ErrJournalLimit
			}
			frame = append(frame, fragment...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				if err != io.EOF {
					return JournalVerification{}, err
				}
				if len(frame) != 0 || !complete || pages == 0 {
					return JournalVerification{}, ErrJournalEvidence
				}
				return JournalVerification{Tenant: start.Tenant, StartSequence: start.Sequence, StartHash: start.Hash, HeadSequence: head.Sequence, HeadHash: head.Hash, Pages: pages, Events: events, ExportSHA256: hex.EncodeToString(hasher.Sum(nil)), MatchesSuppliedCheckpoint: true}, nil
			}
			break
		}
		frames++
		if frames > MaxJournalFrames {
			return JournalVerification{}, ErrJournalLimit
		}
		frame = bytes.TrimSuffix(frame, []byte{'\n'})
		if len(frame) == 0 && pages > 0 && !blank {
			blank = true
			continue
		}
		blank = false
		if complete {
			return JournalVerification{}, ErrJournalEvidence
		}
		page, err := DecodeJournalPage(frame)
		if err != nil {
			return JournalVerification{}, err
		}
		current, err = VerifyJournalPage(ctx, page, current, head)
		if err != nil {
			return JournalVerification{}, err
		}
		if selection != nil && selection.sequence > page.After && selection.sequence <= page.NextAfter {
			for _, event := range page.Items {
				if event.Sequence == selection.sequence {
					selection.event = event
					break
				}
			}
		}
		pages++
		events += int64(len(page.Items))
		complete = !page.More
	}
}
