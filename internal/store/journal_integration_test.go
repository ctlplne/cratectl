//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func TestJournalExportPinsImmutableRangeAndRechecksTenantAndCredentials(t *testing.T) {
	d, s, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, err := s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := s.JournalCheckpoint(ctx, i)
	if err != nil || initial.Sequence != 2 {
		t.Fatal("provisioning history not retained", initial, err)
	}
	appendRows := func(count int) {
		t.Helper()
		if err := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
			for n := 0; n < count; n++ {
				if err := appendEventIntent(ctx, tx, i, "owned.journal.fixture", map[string]any{"ordinal": n, "private": "original body"}, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	appendRows(5)
	head, err := s.JournalCheckpoint(ctx, i)
	if err != nil || head.Sequence != initial.Sequence+5 {
		t.Fatal(head, err)
	}
	input := JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 3}
	first, err := s.JournalPage(ctx, i, input)
	if err != nil || len(first.Items) != 3 || !first.More {
		t.Fatal("first fixed range page", first, err)
	}
	appendRows(2)
	again, err := s.JournalPage(ctx, i, input)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("lost-page reread changed after later publication", err)
	}
	start := crypt.JournalAnchor{Tenant: i.Tenant}
	var export bytes.Buffer
	for {
		page, err := s.JournalPage(ctx, i, input)
		if err != nil || json.NewEncoder(&export).Encode(page) != nil {
			t.Fatal(err)
		}
		if !page.More {
			break
		}
		input.After, input.AfterHash = page.NextAfter, page.NextHash
	}
	verified, err := crypt.VerifyJournalExport(ctx, &export, start, head, 1<<20)
	if err != nil || verified.Events != head.Sequence || !verified.MatchesSuppliedCheckpoint {
		t.Fatal("real database range did not verify offline", verified, err)
	}
	input = JournalRange{Through: head.Sequence, ThroughHash: strings.Repeat("a", 64), Limit: 3}
	if _, err := s.JournalPage(ctx, i, input); !errors.Is(err, ErrJournalChanged) {
		t.Fatal("replaced terminal hash accepted", err)
	}
	input.ThroughHash = head.Hash
	reader := i
	reader.Role, reader.CredentialHash = "reader", ""
	if _, err := s.JournalPage(ctx, reader, input); !errors.Is(err, ErrDenied) {
		t.Fatal("reader exported history", err)
	}
	other := Identity{Tenant: "journal-empty", Actor: "operator", Role: "admin"}
	if _, err := s.JournalPage(ctx, other, input); !errors.Is(err, ErrJournalChanged) {
		t.Fatal("another tenant borrowed identical sequence", err)
	}
	genesis, err := s.JournalCheckpoint(ctx, other)
	if err != nil || genesis.Sequence != 0 || genesis.Hash != "" {
		t.Fatal("empty tenant checkpoint leaked history", genesis, err)
	}
	if page, err := s.JournalPage(ctx, other, JournalRange{Limit: 1}); err != nil || len(page.Items) != 0 || page.More {
		t.Fatal("empty genesis range", err)
	}
	var unscoped int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.events`).Scan(&unscoped); err != nil || unscoped != 0 {
		t.Fatal("unscoped runtime read bypassed forced RLS", unscoped, err)
	}
	if err := Revoke(ctx, d.OwnerDSN, token); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, err := s.JournalCheckpoint(ctx, i); return err },
		func() error { _, err := s.JournalPage(ctx, i, input); return err },
		func() error { _, err := s.JournalEvents(ctx, i, 0, 100); return err },
	} {
		if err := call(); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("stale authenticated identity retained export authority", err)
		}
	}
	expiredToken, _ := crypt.Token()
	if err := Provision(ctx, d.OwnerDSN, i.Tenant, "expired-journal", "admin", expiredToken, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	expired := Identity{Tenant: i.Tenant, Actor: "expired-journal", Role: "admin", CredentialHash: crypt.Digest([]byte(expiredToken))}
	if _, err := s.JournalCheckpoint(ctx, expired); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired checkpoint authority", err)
	}
}

func TestJournalExportBoundsOriginalPayloadBytesAndAdvancingLegacyList(t *testing.T) {
	_, s, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, err := s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		for n := 0; n < 1005; n++ {
			if err := appendEventIntent(ctx, tx, i, "owned.small.fixture", n, false); err != nil {
				return err
			}
		}
		for n := 0; n < 5; n++ {
			if err := appendEventIntent(ctx, tx, i, "owned.large.fixture", strings.Repeat("\x01", 20000), false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first, err := s.JournalEvents(ctx, i, 0, 1000)
	if err != nil || len(first.Items) != 1000 || !first.More || first.NextAfter != 1000 {
		t.Fatal("count-bounded list", err)
	}
	large, err := s.JournalEvents(ctx, i, 1007, 1000)
	raw, marshalErr := json.Marshal(large)
	if err != nil || marshalErr != nil || len(large.Items) < 1 || len(large.Items) >= 5 || !large.More || len(raw)+1 > crypt.MaxJournalPageBytes {
		t.Fatal("byte-bounded list claimed completion or overflowed", len(large.Items), len(raw), err)
	}
	total, cursor := len(large.Items), large.NextAfter
	for total < 5 {
		next, err := s.JournalEvents(ctx, i, cursor, 1000)
		if err != nil || next.NextAfter <= cursor || len(next.Items) == 0 {
			t.Fatal("short byte page lost its advancing cursor", err)
		}
		total, cursor = total+len(next.Items), next.NextAfter
		if !next.More && total != 5 {
			t.Fatal("byte bound silently truncated history")
		}
	}
	if total != 5 || cursor != 1012 {
		t.Fatal("byte pages lost or duplicated an event", total, cursor)
	}
	if page, err := s.JournalEvents(ctx, i, 999999, 1000); err != nil || page.More || len(page.Items) != 0 || page.NextAfter != 999999 {
		t.Fatal("legacy future cursor semantics changed", err)
	}
}

func TestJournalExportRejectsOversizedGappedAndCorruptRetainedHistory(t *testing.T) {
	_, s, _, _, _ := schemaFixture(t)
	ctx := context.Background()
	for _, scenario := range []string{"oversize", "gap", "payload-tenant", "payload-sequence", "payload-changed", "previous-link", "invalid-digest"} {
		t.Run(scenario, func(t *testing.T) {
			i := Identity{Tenant: "journal-" + scenario, Actor: "operator", Role: "admin"}
			payload := `{"tenant":"` + i.Tenant + `","sequence":1}`
			sequence, previous := int64(1), ""
			switch scenario {
			case "oversize":
				payload = strings.Repeat("x", crypt.MaxJournalPayload+1)
			case "gap":
				sequence = 2
			case "payload-tenant":
				payload = `{"tenant":"another-team","sequence":1}`
			case "payload-sequence":
				payload = `{"tenant":"` + i.Tenant + `","sequence":2}`
			case "previous-link":
				previous = strings.Repeat("a", 64)
			}
			hash := crypt.Digest([]byte(previous + "\n" + payload))
			if scenario == "payload-changed" {
				payload += " "
			}
			if scenario == "invalid-digest" {
				hash = strings.Repeat("A", 64)
			}
			if err := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO cratectl.events(tenant,sequence,payload,previous_hash,hash) VALUES($1,$2,$3,$4,$5)`, i.Tenant, sequence, payload, previous, hash)
				return err
			}); err != nil {
				t.Fatal("owned damaged history fixture", err)
			}
			_, err := s.JournalPage(ctx, i, JournalRange{Through: sequence, ThroughHash: strings.ToLower(hash), Limit: 1000})
			want := crypt.ErrJournalEvidence
			if scenario == "oversize" {
				want = crypt.ErrJournalLimit
			} else if scenario == "invalid-digest" {
				want = ErrJournalChanged
			}
			if !errors.Is(err, want) {
				t.Fatal("damaged retained history treated as a clean export", err, want)
			}
		})
	}
}
