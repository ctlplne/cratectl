// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"strconv"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) retentionScheduleManagement(w http.ResponseWriter, r *http.Request, i store.Identity, bits []string) bool {
	if len(bits) > 6 || !store.Name.MatchString(bits[1]) || !store.Name.MatchString(bits[3]) {
		respondErr(w, store.ErrRetentionInput)
		return true
	}
	repo, name := bits[1], bits[3]
	if r.Method == "GET" && len(bits) == 5 {
		if r.URL.RawQuery != "" {
			respondErr(w, store.ErrRetentionInput)
			return true
		}
		out, e := s.DB.RetentionSchedule(r.Context(), i, repo, name)
		if e != nil {
			respondErr(w, e)
		} else {
			writeJSON(w, 200, out)
		}
		return true
	}
	if r.Method == "GET" && len(bits) == 6 {
		after, limit, ok := retentionPage(w, r)
		if !ok {
			return true
		}
		var cursor int64
		var e error
		if after != "" {
			cursor, e = strconv.ParseInt(after, 10, 64)
		}
		if e != nil || cursor < 0 {
			respondErr(w, store.ErrRetentionInput)
			return true
		}
		switch bits[5] {
		case "history":
			items, more, e := s.DB.RetentionScheduleHistory(r.Context(), i, repo, name, cursor, limit)
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, map[string]any{"items": items, "more": more})
			}
		case "runs":
			items, more, e := s.DB.RetentionScheduleRuns(r.Context(), i, repo, name, cursor, limit)
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, map[string]any{"items": items, "more": more})
			}
		default:
			fail(w, 404, "not_found", "Read the retention schedule, configuration history or recorded scheduled runs.")
		}
		return true
	}
	if r.Method != "PUT" || len(bits) != 5 {
		allow := "GET"
		if len(bits) == 5 {
			allow = "GET, PUT"
		}
		w.Header().Set("Allow", allow)
		fail(w, 405, "method_not_allowed", "Read scheduled retirement with GET or preview/replace its exact configuration with PUT.")
		return true
	}
	if r.URL.RawQuery != "" {
		respondErr(w, store.ErrRetentionInput)
		return true
	}
	var request store.RetentionScheduleRequest
	data, ok := readRetentionBody(w, r, &request, "expected_revision", "expected_policy_revision", "expected_source_revision", "interval_seconds", "max_targets", "enabled", "authorize_future_retirements", "reason")
	if !ok {
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !request.DryRun && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key and preserve it for identical retries.")
		return true
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	out, e := s.DB.SetRetentionSchedule(r.Context(), i, repo, name, key, fp, request, min(s.NativeVersionLimit, 10000))
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, out)
	}
	return true
}
