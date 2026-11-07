//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestJournalManagementExportsExactBoundedPagesAndCurrentAuthority(t *testing.T) {
	s, d, token, i := schemaServer(t)
	ctx := context.Background()
	api := lifecycleHTTP(t, s, token)
	w := api("GET", "/api/v1/audit/checkpoint", nil, "")
	var observation struct {
		Checkpoint crypt.JournalAnchor `json:"checkpoint"`
		Signed     bool                `json:"signed"`
		Trust      string              `json:"trust"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &observation) != nil || observation.Signed || observation.Trust == "" || observation.Checkpoint.Sequence != 1 || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("unsigned checkpoint contract", w.Code)
	}
	head := observation.Checkpoint
	q := url.Values{"after": {"0"}, "after_hash": {""}, "through": {strconv.FormatInt(head.Sequence, 10)}, "through_hash": {head.Hash}, "limit": {"1"}}
	path := "/api/v1/audit/export?" + q.Encode()
	first := api("GET", path, nil, "")
	if first.Code != 200 || first.Body.Len() > crypt.MaxJournalPageBytes {
		t.Fatal("bounded export response", first.Code)
	}
	page, err := crypt.DecodeJournalPage(bytes.TrimSuffix(first.Body.Bytes(), []byte{'\n'}))
	if err != nil || page.More || len(page.Items) != 1 {
		t.Fatal("API did not return canonical original event page", err)
	}
	if _, err := crypt.VerifyJournalExport(ctx, bytes.NewReader(first.Body.Bytes()), crypt.JournalAnchor{Tenant: i.Tenant}, head, 1<<20); err != nil {
		t.Fatal("real API response failed independent offline range verification", err)
	}
	if w := api("POST", "/api/v1/repositories", store.Repository{Name: "journal-later", Format: "generic"}, "journal-later-mutation"); w.Code != 201 {
		t.Fatal("later actual mutation", w.Code)
	}
	if w := api("GET", path, nil, ""); w.Code != 200 || !bytes.Equal(first.Body.Bytes(), w.Body.Bytes()) {
		t.Fatal("fixed terminal changed when current head advanced", w.Code)
	}
	q.Set("through_hash", strings.Repeat("a", 64))
	if w := api("GET", "/api/v1/audit/export?"+q.Encode(), nil, ""); w.Code != 409 || !strings.Contains(w.Body.String(), "journal_checkpoint_changed") || strings.Contains(w.Body.String(), "identity.provisioned") {
		t.Fatal("different checkpoint accepted or reflected private events", w.Code)
	}
	list := api("GET", "/api/v1/audit?limit=1", nil, "")
	var listed struct {
		Items     []crypt.JournalEvent
		More      bool
		NextAfter int64 `json:"next_after"`
		Limit     int
	}
	if list.Code != 200 || json.Unmarshal(list.Body.Bytes(), &listed) != nil || !listed.More || listed.NextAfter != 1 || listed.Limit != 1 {
		t.Fatal("legacy list lacks explicit advancing cursor", list.Code)
	}
	reader, _ := crypt.Token()
	if err := store.Provision(ctx, d.OwnerDSN, i.Tenant, "journal-reader", "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"/api/v1/audit", "/api/v1/audit/checkpoint", path} {
		if w := lifecycleHTTP(t, s, reader)("GET", endpoint, nil, ""); w.Code != 403 {
			t.Fatal("reader inspected private journal", endpoint, w.Code)
		}
	}
	if err := store.Revoke(ctx, d.OwnerDSN, token); err != nil {
		t.Fatal(err)
	}
	if w := api("GET", path, nil, ""); w.Code != 401 {
		t.Fatal("revoked authority could reread retained page", w.Code)
	}
}
