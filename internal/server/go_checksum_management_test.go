// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestGoChecksumManagementRejectsAmbiguousQueriesBeforeDatabaseWork(t *testing.T) {
	s := &Server{}
	base := "repositories/owned/go/checksum"
	for _, path := range []string{
		base, base + "?source_revision=-1", base + "?source_revision=00", base + "?source_revision=+1", base + "?source_revision=1&source_revision=1", base + "?source_revision=0&unknown=x", base + "?source_revision=", base + "?source_revision=9223372036854775808", base + "?source_revision=%zz", base + "?source_revision=0;unknown=x", base + "?source_revision=0&padding=" + strings.Repeat("x", 8192),
		base + "/failures?limit=0", base + "/failures?limit=101", base + "/failures?after=-1", base + "/failures?after=01", base + "/failures?limit=", base + "/failures?after=0&after=1", base + "/failures?source_revision=0",
		base + "/failures/evidence?source_revision=0&generation=0&root_path=bad", base + "/failures/evidence?source_revision=0&generation=1", base + "/failures/evidence?generation=1&root_path=bad", base + "/failures/evidence?source_revision=0&generation=1&root_path=bad",
	} {
		t.Run(path[:min(len(path), 120)], func(t *testing.T) {
			p, q, _ := strings.Cut(path, "?")
			r := httptest.NewRequest("GET", "/", nil)
			r.URL.RawQuery = q
			w := httptest.NewRecorder()
			if !s.goChecksumManagement(w, r, store.Identity{}, p) || w.Code != 400 {
				t.Fatal("ambiguous input reached database or wrong response", w.Code, w.Body.String())
			}
		})
	}
}

func TestGoChecksumManagementMatchesOnlyExactReadOnlySegments(t *testing.T) {
	s := &Server{}
	for _, p := range []string{"repositories/checksum", "repositories/go/checksum", "repositories/owned/x/go/checksum", "repositories/owned/go/checksum/unknown", "repositories/owned/go/checksum/failures/evidence/more", "repositories/owned/go/checksum/", "repositories/Owned/go/checksum"} {
		if s.goChecksumManagement(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), store.Identity{}, p) {
			t.Fatal("unrelated route matched checksum management", p)
		}
	}
	for _, suffix := range []string{"", "/failures", "/failures/evidence"} {
		w := httptest.NewRecorder()
		if !s.goChecksumManagement(w, httptest.NewRequest("PUT", "/", nil), store.Identity{}, "repositories/owned/go/checksum"+suffix) || w.Code != 405 || w.Header().Get("Allow") != "GET" {
			t.Fatal("inspection endpoint permitted a trust mutation", w.Code)
		}
	}
}
