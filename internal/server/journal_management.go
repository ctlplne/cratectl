// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"net/url"
	"strconv"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func journalQuery(raw string, allowed ...string) (url.Values, bool) {
	if len(raw) > 8192 {
		return nil, false
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, false
	}
	for name, values := range q {
		found := false
		for _, key := range allowed {
			found = found || name == key
		}
		if !found || len(values) != 1 {
			return nil, false
		}
	}
	return q, true
}

func journalInteger(q url.Values, name string, fallback int64) (int64, bool) {
	values, exists := q[name]
	if !exists {
		return fallback, true
	}
	if len(values) != 1 {
		return 0, false
	}
	n, err := strconv.ParseInt(values[0], 10, 64)
	return n, err == nil && n >= 0 && strconv.FormatInt(n, 10) == values[0]
}

func (s *Server) journalManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) bool {
	if path != "audit" && path != "audit/checkpoint" && path != "audit/export" {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Read retained journal evidence with GET. Export never changes history or its trust checkpoint.")
		return true
	}
	if path == "audit/checkpoint" {
		if r.URL.RawQuery != "" {
			respondErr(w, store.ErrJournalInput)
			return true
		}
		anchor, err := s.DB.JournalCheckpoint(r.Context(), i)
		if err != nil {
			respondErr(w, err)
		} else {
			writeJSON(w, 200, map[string]any{"checkpoint": anchor, "signed": false, "trust": "Authenticate this exact tenant, sequence and hash through a separate trusted record or external signer before offline attribution."})
		}
		return true
	}
	allowed := []string{"after", "limit"}
	if path == "audit/export" {
		allowed = append(allowed, "after_hash", "through", "through_hash")
	}
	q, valid := journalQuery(r.URL.RawQuery, allowed...)
	after, a := journalInteger(q, "after", 0)
	defaultLimit := int64(100)
	if path == "audit" {
		defaultLimit = 1000
	}
	limit, l := journalInteger(q, "limit", defaultLimit)
	if !valid || !a || !l || limit < 1 || limit > crypt.MaxJournalPageEvents {
		respondErr(w, store.ErrJournalInput)
		return true
	}
	if path == "audit" {
		page, err := s.DB.JournalEvents(r.Context(), i, after, int(limit))
		if err != nil {
			respondErr(w, err)
		} else {
			writeJSON(w, 200, map[string]any{"items": page.Items, "limit": limit, "more": page.More, "next_after": page.NextAfter})
		}
		return true
	}
	through, h := journalInteger(q, "through", -1)
	start := crypt.JournalAnchor{Tenant: i.Tenant, Sequence: after, Hash: q.Get("after_hash")}
	head := crypt.JournalAnchor{Tenant: i.Tenant, Sequence: through, Hash: q.Get("through_hash")}
	if !h || !start.Valid() || !head.Valid() || after > through || len(q["after"]) != 1 || len(q["after_hash"]) != 1 || len(q["through"]) != 1 || len(q["through_hash"]) != 1 {
		respondErr(w, store.ErrJournalInput)
		return true
	}
	page, err := s.DB.JournalPage(r.Context(), i, store.JournalRange{After: after, AfterHash: start.Hash, Through: through, ThroughHash: head.Hash, Limit: int(limit)})
	if err != nil {
		respondErr(w, err)
	} else {
		// The struct field order is the versioned canonical JSONL export format.
		writeJSON(w, 200, page)
	}
	return true
}
