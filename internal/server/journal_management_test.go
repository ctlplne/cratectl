// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestJournalManagementRejectsAmbiguousRangesBeforeDatabase(t *testing.T) {
	s := &Server{}
	i := store.Identity{Tenant: "owned", Role: "admin"}
	valid := "after=0&after_hash=&through=1&through_hash=" + strings.Repeat("a", 64)
	for _, target := range []string{
		"audit?after=-1", "audit?after=00", "audit?after=+1", "audit?after=", "audit?after=9223372036854775808", "audit?limit=0", "audit?limit=1001", "audit?limit=", "audit?after=0&after=1", "audit?unknown=x", "audit?after=%zz", "audit?after=0;limit=10", "audit?pad=" + strings.Repeat("x", 8192),
		"audit/checkpoint?limit=1", "audit/export", "audit/export?" + valid + "&after_hash=", "audit/export?" + valid + "&extra=1", "audit/export?after=0&through=0&through_hash=", "audit/export?after=1&after_hash=&through=1&through_hash=", "audit/export?after=1&after_hash=" + strings.Repeat("a", 64) + "&through=0&through_hash=", "audit/export?" + strings.ReplaceAll(valid, "through=1", "through=01"), "audit/export?" + strings.ReplaceAll(valid, strings.Repeat("a", 64), strings.Repeat("A", 64)),
	} {
		t.Run(target[:min(len(target), 120)], func(t *testing.T) {
			path, query, _ := strings.Cut(target, "?")
			r := httptest.NewRequest("GET", "/", nil)
			r.URL.RawQuery = query
			w := httptest.NewRecorder()
			if !s.journalManagement(w, r, i, path) || w.Code != 400 {
				t.Fatal("ambiguous journal range reached database", w.Code)
			}
		})
	}
}

func TestJournalManagementIsExactReadOnlyAndAdministratorScoped(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"audit/", "audit/export/", "audit/other", "audit/checkpoint/sign", "audits"} {
		if s.journalManagement(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), store.Identity{}, path) {
			t.Fatal("unrelated route matched", path)
		}
	}
	for _, path := range []string{"audit", "audit/export", "audit/checkpoint"} {
		w := httptest.NewRecorder()
		if !s.journalManagement(w, httptest.NewRequest("POST", "/", nil), store.Identity{Role: "admin"}, path) || w.Code != 405 || w.Header().Get("Allow") != "GET" {
			t.Fatal("journal route permitted a mutation", w.Code)
		}
		w = httptest.NewRecorder()
		if !s.journalManagement(w, httptest.NewRequest("GET", "/", nil), store.Identity{Role: "reader"}, path) || w.Code != 403 {
			t.Fatal("reader reached journal export database", w.Code)
		}
	}
}
