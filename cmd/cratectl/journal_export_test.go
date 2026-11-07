// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

type journalTransport func(*http.Request) (*http.Response, error)

func (f journalTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJournalCollectionFollowsPinnedPagesAndRejectsIncompleteOrChangedResponses(t *testing.T) {
	tenant := "owned-team"
	previous := ""
	var events []crypt.JournalEvent
	for n := int64(1); n <= 2; n++ {
		payload, _ := json.Marshal(map[string]any{"tenant": tenant, "sequence": n})
		event := crypt.JournalEvent{Sequence: n, Payload: string(payload), PreviousHash: previous, Hash: crypt.Digest([]byte(previous + "\n" + string(payload)))}
		events, previous = append(events, event), event.Hash
	}
	head := crypt.JournalAnchor{Tenant: tenant, Sequence: 2, Hash: previous}
	for _, scenario := range []string{"complete", "repeated-page", "changed-head", "changed-tenant", "denied-second", "redirect", "network-error", "missing-newline", "unknown-field", "overflow", "byte-limit", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: journalTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				q := r.URL.Query()
				if r.Method != "GET" || r.URL.Path != "/api/v1/audit/export" || q.Get("through") != "2" || q.Get("through_hash") != head.Hash || q.Get("limit") != "1" || r.Header.Get("Authorization") != "Bearer owned-secret" || q.Get("after") != []string{"0", "1"}[calls-1] || q.Get("after_hash") != []string{"", events[0].Hash}[calls-1] {
					t.Fatal("collector changed fixed range, credential or cursor")
				}
				if scenario == "network-error" {
					return nil, errors.New("owned network failure")
				}
				page := crypt.JournalPage{Version: 1, Tenant: tenant, Through: 2, ThroughHash: head.Hash, Items: events[:1], More: true, NextAfter: 1, NextHash: events[0].Hash}
				if calls == 2 && scenario != "repeated-page" {
					page.After, page.AfterHash, page.Items, page.More, page.NextAfter, page.NextHash = 1, events[0].Hash, events[1:], false, 2, head.Hash
				}
				if scenario == "changed-head" {
					page.ThroughHash = strings.Repeat("a", 64)
				}
				if scenario == "changed-tenant" {
					page.Tenant = "another-team"
				}
				raw, _ := json.Marshal(page)
				if scenario == "unknown-field" {
					raw = append([]byte(`{"extra":true,`), raw[1:]...)
				}
				if scenario == "overflow" {
					raw = bytes.Repeat([]byte("x"), crypt.MaxJournalPageBytes+1)
				}
				if scenario != "missing-newline" {
					raw = append(raw, '\n')
				}
				status := 200
				if scenario == "denied-second" && calls == 2 {
					status = 403
				}
				if scenario == "redirect" {
					status = 302
				}
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}
			ctx := context.Background()
			if scenario == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			file, err := os.OpenFile(filepath.Join(t.TempDir(), "export.jsonl"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			budget := int64(1 << 20)
			if scenario == "byte-limit" {
				budget = 1
			}
			receipt, err := collectJournal(ctx, client, "https://cratectl.invalid", "owned-secret", file, crypt.JournalAnchor{Tenant: tenant}, head, 1, budget)
			if scenario == "complete" {
				if err != nil || calls != 2 || receipt.Events != 2 || !receipt.MatchesSuppliedCheckpoint {
					t.Fatal("pinned collection failed", receipt, err)
				}
			} else if err == nil || !reflect.DeepEqual(receipt, crypt.JournalVerification{}) {
				t.Fatal("partial or changed response emitted success", receipt, err)
			}
		})
	}
}
