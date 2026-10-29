// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) ConfigureSweepBudget(targets int) error {
	if targets < 1 || targets > 2147483646 {
		return store.ErrConflict
	}
	s.SweepTargetBudget = targets
	return nil
}
func (s *Server) sweepManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) {
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return
	}
	parts := strings.Split(p, "/")
	if r.Method == "GET" {
		query := r.URL.Query()
		limit, after := 100, int64(0)
		var e error
		if len(query["limit"]) > 1 || len(query["after"]) > 1 || len(query["repository"]) > 1 {
			respondErr(w, store.ErrConflict)
			return
		}
		if query.Get("limit") != "" {
			limit, e = strconv.Atoi(query.Get("limit"))
		}
		if e != nil || limit < 1 || limit > 1000 {
			fail(w, 400, "invalid_pagination", "Use limit 1–1000.")
			return
		}
		if query.Get("after") != "" {
			after, e = strconv.ParseInt(query.Get("after"), 10, 64)
		}
		if e != nil || after < 0 {
			fail(w, 400, "invalid_pagination", "Use the last target ordinal as after.")
			return
		}
		switch {
		case len(parts) == 2:
			items, more, e := s.DB.PreviewSweep(r.Context(), i, store.SweepRequest{Repository: query.Get("repository")}, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "target_budget": s.SweepTargetBudget, "security_approval": false, "scope": "Preview only; admission snapshots all referenced artifact and retained OCI upload-part bindings. Unreferenced CAS and temporary files require separate inventory."})
		case len(parts) == 3:
			value, e := s.DB.Sweep(r.Context(), i, parts[2])
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, value)
		case len(parts) == 4 && parts[3] == "items":
			items, more, e := s.DB.SweepItems(r.Context(), i, parts[2], after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "security_approval": false})
		default:
			fail(w, 404, "not_found", "Use the integrity sweep detail or items endpoint.")
		}
		return
	}
	if r.Method != "POST" || len(parts) != 2 {
		fail(w, 405, "method_not_allowed", "POST a new sweep or GET its progress and targets; control it through the jobs API.")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key for the identical snapshot request.")
		return
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		fail(w, 413, "request_limit", "Send less than 8 KiB of sweep JSON.")
		return
	}
	var request store.SweepRequest
	if !decodeManagement(data, &request) || request.Validate() != nil {
		fail(w, 400, "invalid_sweep", "Send an optional repository; omit it to inspect the authenticated tenant's referenced content.")
		return
	}
	fingerprint := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	result, e := s.DB.StartSweep(r.Context(), i, key, fingerprint, request, s.SweepTargetBudget)
	if e != nil {
		respondErr(w, e)
		return
	}
	if result.Replay {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	w.Write(result.Body)
}
