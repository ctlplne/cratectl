// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func decodeScheduleRequest(data []byte) (store.ScheduleRequest, bool) {
	var input store.ScheduleRequest
	var fields map[string]json.RawMessage
	if len(data) > 8192 || !utf8.Valid(data) || uniqueOCIJSON(data) != nil || !decodeManagement(data, &input) || json.Unmarshal(data, &fields) != nil || input.Validate() != nil {
		return input, false
	}
	for _, key := range []string{"expected_revision", "interval_seconds", "sample_size", "enabled", "reason"} {
		if fields[key] == nil || string(fields[key]) == "null" {
			return input, false
		}
	}
	for key, raw := range fields {
		switch key {
		case "repository", "expected_revision", "interval_seconds", "sample_size", "enabled", "reason", "dry_run", "run_immediately":
			if string(raw) == "null" {
				return input, false
			}
		default:
			return input, false
		}
	}
	return input, true
}
func (s *Server) scheduleManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) {
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) > 4 || len(parts) < 2 {
		fail(w, 404, "not_found", "Use the integrity schedule collection, named configuration, history or runs.")
		return
	}
	name := ""
	if len(parts) >= 3 {
		name = parts[2]
		if !store.Name.MatchString(name) {
			respondErr(w, store.ErrScheduleInput)
			return
		}
	}
	if r.Method == "GET" {
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		if queryErr != nil {
			respondErr(w, store.ErrScheduleInput)
			return
		}
		for key, values := range query {
			if (key != "after" && key != "limit") || len(values) != 1 {
				respondErr(w, store.ErrScheduleInput)
				return
			}
		}
		limit := 50
		var e error
		if query.Has("limit") {
			limit, e = strconv.Atoi(query.Get("limit"))
		}
		if e != nil || limit < 1 || limit > 100 {
			respondErr(w, store.ErrScheduleInput)
			return
		}
		if len(parts) == 2 {
			items, more, e := s.DB.IntegritySchedules(r.Context(), i, query.Get("after"), limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "target_budget": s.SweepTargetBudget, "scope": "Recurring bounded reference samples; no full-volume or security approval."})
			return
		}
		if len(parts) == 3 {
			if r.URL.RawQuery != "" {
				respondErr(w, store.ErrScheduleInput)
				return
			}
			out, e := s.DB.IntegritySchedule(r.Context(), i, name)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		after := int64(0)
		if query.Has("after") {
			after, e = strconv.ParseInt(query.Get("after"), 10, 64)
		}
		if e != nil || after < 0 {
			respondErr(w, store.ErrScheduleInput)
			return
		}
		switch parts[3] {
		case "history":
			items, more, e := s.DB.IntegrityScheduleHistory(r.Context(), i, name, after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more})
		case "runs":
			items, more, e := s.DB.IntegrityScheduleRuns(r.Context(), i, name, after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "security_approval": false, "all_tenant_content_assessed": false})
		default:
			fail(w, 404, "not_found", "Read a schedule's history or runs.")
		}
		return
	}
	if r.Method != "PUT" || len(parts) != 3 {
		fail(w, 405, "method_not_allowed", "PUT an exact-revision schedule configuration, or GET its configuration, history and runs.")
		return
	}
	if r.URL.RawQuery != "" {
		respondErr(w, store.ErrScheduleInput)
		return
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		fail(w, 413, "request_limit", "Limit schedule configuration to 8 KiB.")
		return
	}
	input, valid := decodeScheduleRequest(data)
	if !valid {
		respondErr(w, store.ErrScheduleInput)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !input.DryRun && !repairKey(key) {
		fail(w, 400, "idempotency_key_required", "Use an 8–128 character Idempotency-Key for the identical schedule configuration.")
		return
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	result, e := s.DB.SetIntegritySchedule(r.Context(), i, name, key, fp, input, s.SweepTargetBudget)
	if e != nil {
		respondErr(w, e)
		return
	}
	writeLifecycleResult(w, result)
}
