// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

// Exact segment matching prevents repository names from selecting subroutes.
// All three endpoints are observations; none rehabilitates a blocked key.
func (s *Server) goChecksumManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) bool {
	p := strings.Split(path, "/")
	if len(p) < 4 || p[0] != "repositories" || !store.Name.MatchString(p[1]) || p[2] != "go" || p[3] != "checksum" {
		return false
	}
	if len(p) != 4 && !(len(p) == 5 && p[4] == "failures") && !(len(p) == 6 && p[4] == "failures" && p[5] == "evidence") {
		return false
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Inspect checksum state and retained evidence with GET. This endpoint cannot reset trust.")
		return true
	}
	if len(r.URL.RawQuery) > 8192 {
		fail(w, 400, "invalid_checksum_query", "Limit the checksum query to 8192 bytes.")
		return true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	allowed := map[string]bool{"source_revision": true}
	if len(p) == 5 {
		allowed = map[string]bool{"after": true, "limit": true}
	} else if len(p) == 6 {
		allowed["root_path"], allowed["generation"] = true, true
	}
	valid := err == nil && len(r.URL.RawQuery) <= 8192
	for k, v := range q {
		valid = valid && allowed[k] && len(v) == 1 && v[0] != ""
	}
	integer := func(name string, fallback int64) (int64, bool) {
		v, exists := q[name]
		if !exists {
			return fallback, true
		}
		n, err := strconv.ParseInt(v[0], 10, 64)
		return n, err == nil && n >= 0 && strconv.FormatInt(n, 10) == v[0]
	}
	if !valid {
		fail(w, 400, "invalid_checksum_query", "Use one value for each documented query field within 8192 bytes.")
		return true
	}
	if len(p) == 5 {
		after, a := integer("after", 0)
		limit, b := integer("limit", 25)
		if !a || !b || limit < 1 || limit > 100 {
			fail(w, 400, "invalid_checksum_query", "Use a nonnegative after sequence and a limit from 1 through 100.")
			return true
		}
		items, more, err := s.DB.GoChecksumFailurePage(r.Context(), i, p[1], after, int(limit))
		if err != nil {
			respondErr(w, err)
			return true
		}
		next := int64(0)
		if more {
			next = items[len(items)-1].Sequence
		}
		writeJSON(w, 200, map[string]any{"items": items, "more": more, "next_after": next, "limit": limit})
		return true
	}
	revision, validRevision := integer("source_revision", -1)
	if !validRevision || revision < 0 {
		fail(w, 400, "invalid_checksum_query", "Supply the exact nonnegative source_revision observed for the repository.")
		return true
	}
	if len(p) == 4 {
		state, err := s.DB.GoChecksumState(r.Context(), i, p[1], revision)
		if err != nil {
			respondErr(w, err)
			return true
		}
		writeJSON(w, 200, map[string]any{"source_revision": revision, "authority": state, "package_admission": false})
		return true
	}
	generation, validGeneration := integer("generation", -1)
	if !validGeneration || generation <= 0 || q.Get("root_path") == "" {
		fail(w, 400, "invalid_checksum_query", "Supply root_path, its historical source_revision and a positive failure generation from the failure history.")
		return true
	}
	root, rootErr := gomodule.ParseRequest(q.Get("root_path"))
	if rootErr != nil || root.Operation != "zip" {
		fail(w, 400, "invalid_checksum_query", "Use the canonical module ZIP root_path recorded in the failure history.")
		return true
	}
	raw, digest, err := s.DB.GoChecksumFailureEvidence(r.Context(), i, p[1], q.Get("root_path"), revision, generation)
	if err != nil {
		respondErr(w, err)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="go-checksum-failure.json"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("X-Cratectl-Evidence-SHA256", digest)
	w.WriteHeader(200)
	_, _ = w.Write(raw)
	return true
}
