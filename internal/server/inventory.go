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

func (s *Server) ConfigureInventory(entries, directory int) error {
	limits := store.InventoryLimits{MaxEntries: entries, DirectoryEntries: directory}
	if e := limits.Validate(1); e != nil {
		return e
	}
	s.InventoryLimits = limits
	return nil
}
func (s *Server) inventoryManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) {
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return
	}
	parts := strings.Split(p, "/")
	if r.Method == "GET" {
		query := r.URL.Query()
		limit := 100
		after := int64(0)
		var e error
		for _, key := range []string{"limit", "after", "state", "area"} {
			if len(query[key]) > 1 {
				respondErr(w, store.ErrConflict)
				return
			}
		}
		if query.Get("limit") != "" {
			limit, e = strconv.Atoi(query.Get("limit"))
		}
		if e != nil || limit < 1 || limit > 1000 {
			fail(w, 400, "invalid_pagination", "Use limit 1–1000.")
			return
		}
		if len(parts) > 3 && query.Get("after") != "" {
			after, e = strconv.ParseInt(query.Get("after"), 10, 64)
		}
		if e != nil || after < 0 {
			fail(w, 400, "invalid_pagination", "Use the last returned ordinal as after.")
			return
		}
		switch {
		case len(parts) == 2:
			items, next, e := s.DB.Inventories(r.Context(), i, query.Get("state"), query.Get("after"), limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "next": next})
		case len(parts) == 3:
			value, e := s.DB.Inventory(r.Context(), i, parts[2])
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, value)
		case len(parts) == 4 && parts[3] == "items":
			items, more, e := s.DB.InventoryItems(r.Context(), i, parts[2], query.Get("area"), after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "safe_to_delete": false, "security_approval": false})
		case len(parts) == 4 && parts[3] == "references":
			items, more, e := s.DB.InventoryReferences(r.Context(), i, parts[2], after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "security_approval": false})
		case len(parts) == 4 && parts[3] == "observations":
			items, more, e := s.DB.InventoryObservations(r.Context(), i, parts[2], after, limit)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "more": more, "security_approval": false})
		default:
			fail(w, 404, "not_found", "Use the inventory detail, items or references endpoint.")
		}
		return
	}
	if r.Method != "POST" || len(parts) != 2 {
		fail(w, 405, "method_not_allowed", "POST a new inventory or GET its progress; control it through the jobs API.")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key for this identical inventory request.")
		return
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		fail(w, 413, "request_limit", "Send less than 8 KiB of inventory JSON.")
		return
	}
	input := store.InventoryRequest{PageSize: min(100, s.InventoryLimits.DirectoryEntries)}
	if !decodeManagement(data, &input) || input.PageSize < 1 || input.PageSize > 1000 {
		fail(w, 400, "invalid_inventory", "Choose page_size 1–1000 within the operator directory budget; this operation inventories the authenticated tenant.")
		return
	}
	fingerprint := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	if prior, found, e := s.DB.ReplayMutation(r.Context(), i, key, fingerprint); e != nil {
		respondErr(w, e)
		return
	} else if found {
		w.Header().Set("Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(prior.Status)
		w.Write(prior.Body)
		return
	}
	if s.InventoryLimits.Validate(input.PageSize) != nil {
		fail(w, 400, "invalid_inventory", "Choose page_size within the operator directory budget.")
		return
	}
	root, e := s.Blobs.InventoryRoot(i.Tenant)
	if e != nil {
		respondErr(w, e)
		return
	}
	result, e := s.DB.StartInventory(r.Context(), i, key, fingerprint, root, input, s.InventoryLimits, s.SweepTargetBudget)
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
