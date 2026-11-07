// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func legacyReviewJSON(t *testing.T) []byte {
	t.Helper()
	in := legacyChecksumReviewInput{Repository: "source", GoChecksumLegacyReviewRequest: store.GoChecksumLegacyReviewRequest{DryRun: true, IncidentHash: strings.Repeat("1", 64), KeyDigest: strings.Repeat("2", 64), CheckpointSHA256: strings.Repeat("3", 64), ReviewReferenceSHA256: strings.Repeat("4", 64), Reason: "Owned external trust review"}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLegacyChecksumReviewJSONRejectsMissingNullDuplicateAndCaseAliasBindings(t *testing.T) {
	raw := legacyReviewJSON(t)
	if in, ok := decodeLegacyChecksumReview(raw); !ok || in.Repository != "source" || !in.DryRun {
		t.Fatal("valid explicit preview rejected")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for name, value := range fields {
		t.Run(name, func(t *testing.T) {
			for _, alias := range []string{name, strings.ToUpper(name[:1]) + name[1:]} {
				withAlias := append([]byte(fmt.Sprintf("{%q:%s,", alias, value)), raw[1:]...)
				if _, ok := decodeLegacyChecksumReview(withAlias); ok {
					t.Fatal("duplicate or case alias review binding accepted", alias)
				}
			}
			if name == "accept_unattributed_history" {
				return
			}
			for _, mode := range []string{"missing", "null"} {
				modified := map[string]json.RawMessage{}
				for k, v := range fields {
					modified[k] = v
				}
				if mode == "missing" {
					delete(modified, name)
				} else {
					modified[name] = json.RawMessage("null")
				}
				bad, err := json.Marshal(modified)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := decodeLegacyChecksumReview(bad); ok {
					t.Fatal("missing/null exact binding accepted", name, mode)
				}
			}
		})
	}
	for _, bad := range [][]byte{[]byte("{"), []byte("[]"), append(append([]byte{}, raw...), []byte(" {}")...), append([]byte(`{"unknown":true,`), raw[1:]...), []byte{0xff}, []byte(strings.Repeat(" ", 64<<10+1))} {
		if _, ok := decodeLegacyChecksumReview(bad); ok {
			t.Fatal("invalid review JSON accepted")
		}
	}
}

func TestLegacyChecksumManagementRejectsAmbiguousInputWithoutDatabaseAccess(t *testing.T) {
	s := &Server{}
	admin := store.Identity{Role: "admin"}
	base := "go/checksum/legacy-incidents"
	for _, query := range []string{"limit=0", "limit=101", "after=-1", "after=01", "after=0&after=1", "limit=", "key_digest=", "unknown=x", "after=%zz", "after=0;limit=1", "padding=" + strings.Repeat("x", 8192)} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		if !s.goChecksumLegacyManagement(w, r, admin, base) || w.Code != 400 {
			t.Fatal("ambiguous query reached database", query, w.Code)
		}
	}
	for _, suffix := range []string{"/0", "/-1", "/01", "/9223372036854775808", "/x", "/7?unknown=x"} {
		p, q, _ := strings.Cut(base+suffix, "?")
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.RawQuery = q
		w := httptest.NewRecorder()
		if !s.goChecksumLegacyManagement(w, r, admin, p) || w.Code != 400 {
			t.Fatal("invalid incident selector reached database", suffix, w.Code)
		}
	}
	for _, p := range []string{base, base + "/7", base + "/7/reviews"} {
		w := httptest.NewRecorder()
		if !s.goChecksumLegacyManagement(w, httptest.NewRequest("GET", "/", nil), store.Identity{Role: "reader"}, p) || w.Code != 403 {
			t.Fatal("reader reached tenant incident detail/review", p, w.Code)
		}
	}
	for _, p := range []string{"repositories/legacy-incidents", "go/checksum", "go/checksum/legacy-incidents/7/reviews/more", "go/checksum/legacy-incidents/7/other"} {
		if s.goChecksumLegacyManagement(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), admin, p) {
			t.Fatal("unrelated management route matched", p)
		}
	}
}

func TestLegacyChecksumErrorsDoNotInventProofOrExposeOriginalContext(t *testing.T) {
	for _, e := range []error{store.ErrGoChecksumLegacyReview, store.ErrGoChecksumLegacyInput, store.ErrGoChecksumLegacyChanged} {
		w := httptest.NewRecorder()
		respondErr(w, fmt.Errorf("private unrelated module: %w", e))
		if w.Code != 400 && w.Code != 409 || strings.Contains(w.Body.String(), "private unrelated module") || strings.Contains(w.Body.String(), "authenticated conflicting history") {
			t.Fatal("legacy label became proof or exposed private context", w.Code, w.Body.String())
		}
	}
	if got := goModuleFillFailure(store.ErrGoChecksumLegacyReview); got != "upstream_checksum_legacy_review" {
		t.Fatal("legacy review failure lost stable classification", got)
	}
}
