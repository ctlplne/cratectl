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

func (s *Server) jobManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) {
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return
	}
	parts := strings.Split(p, "/")
	if r.Method == "GET" {
		limit := 100
		values, e := r.URL.Query(), error(nil)
		if len(values["limit"]) > 1 || len(values["after"]) > 1 || len(values["queue"]) > 1 || len(values["state"]) > 1 {
			respondErr(w, store.ErrConflict)
			return
		}
		if raw := values.Get("limit"); raw != "" {
			limit, e = strconv.Atoi(raw)
		}
		if e != nil || limit < 1 || limit > 1000 {
			fail(w, 400, "invalid_pagination", "Use limit 1–1000 and the returned cursor.")
			return
		}
		switch {
		case p == "maintenance/reconciliations":
			input := store.ReconciliationRequest{Repository: values.Get("repository"), PageSize: limit}
			if len(values["repository"]) > 1 {
				respondErr(w, store.ErrConflict)
				return
			}
			preview, e := s.DB.PreviewReconciliation(r.Context(), i, input)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, preview)
		case p == "jobs":
			items, next, e := s.DB.Jobs(r.Context(), i, values.Get("queue"), values.Get("state"), values.Get("after"), limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "next": next})
		case p == "jobs/queues":
			items, e := s.DB.Queues(r.Context(), i)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
		case p == "activity":
			after := int64(0)
			if values.Get("after") != "" {
				after, e = strconv.ParseInt(values.Get("after"), 10, 64)
			}
			if e != nil || after < 0 {
				respondErr(w, store.ErrConflict)
				return
			}
			items, more, e := s.DB.Activity(r.Context(), i, after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "scope": "Asynchronous source-event index; the audit journal remains authoritative."})
		case len(parts) == 2:
			value, e := s.DB.Job(r.Context(), i, parts[1])
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, value)
		case len(parts) == 3 && parts[2] == "observations":
			after := int64(0)
			if values.Get("after") != "" {
				after, e = strconv.ParseInt(values.Get("after"), 10, 64)
			}
			if e != nil || after < 0 {
				respondErr(w, store.ErrConflict)
				return
			}
			items, more, e := s.DB.JobObservations(r.Context(), i, parts[1], after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "assessment_kind": "storage_integrity", "security_approval": false})
		default:
			fail(w, 404, "not_found", "Use a documented jobs endpoint.")
		}
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key for this identical request.")
		return
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		fail(w, 413, "request_limit", "Use less than 8 KiB of job control JSON.")
		return
	}
	fingerprint := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	var result store.Result
	switch {
	case p == "maintenance/reconciliations" && r.Method == "POST":
		input := store.ReconciliationRequest{PageSize: 100}
		if !decodeManagement(data, &input) || input.Validate() != nil {
			fail(w, 400, "invalid_reconciliation", "Use an optional repository and page_size 1–1000.")
			return
		}
		result, e = s.DB.StartReconciliation(r.Context(), i, key, fingerprint, input)
	case len(parts) == 3 && parts[1] == "queues" && r.Method == "PUT":
		var policy store.QueuePolicy
		if !decodeManagement(data, &policy) || policy.Queue != "" && policy.Queue != parts[2] {
			fail(w, 400, "invalid_queue_policy", "Choose one documented lane and positive operator resource budgets.")
			return
		}
		policy.Queue = parts[2]
		if policy.Validate() != nil {
			fail(w, 400, "invalid_queue_policy", "Use positive capacity/concurrency/attempts and retry seconds within the documented bounds.")
			return
		}
		result, e = s.DB.SetQueuePolicy(r.Context(), i, key, fingerprint, policy)
	case len(parts) == 3 && (parts[2] == "retry" || parts[2] == "cancel") && r.Method == "POST":
		var input struct {
			AcknowledgeUnknown bool `json:"acknowledge_unknown"`
		}
		if !decodeManagement(data, &input) {
			fail(w, 400, "invalid_json", "Send a JSON object; explicitly acknowledge an uncertain remote outcome before retrying it.")
			return
		}
		result, e = s.DB.ControlJob(r.Context(), i, key, fingerprint, parts[1], parts[2], input.AcknowledgeUnknown)
	default:
		fail(w, 404, "not_found", "Use a documented jobs mutation endpoint.")
		return
	}
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
