// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) holdCaseManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	bits := strings.Split(p, "/")
	list := p == "hold-cases"
	item := (len(bits) == 5 || len(bits) == 6 && bits[5] == "history") && bits[0] == "repositories" && bits[2] == "artifacts" && bits[3] == "holds"
	if !list && !item {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	history := item && len(bits) == 6
	if item && (!store.Name.MatchString(bits[1]) || !store.Name.MatchString(bits[4]) || bits[4] == "legacy") {
		fail(w, 400, "invalid_hold_case", "Choose a repository and a case name; legacy is reserved for the original hold slot.")
		return true
	}
	if r.Method == "PUT" && item && !history {
		s.putHoldCase(w, r, i, bits[1], bits[4])
		return true
	}
	if r.Method != "GET" {
		allow := "GET"
		if item && !history {
			allow = "GET, PUT"
		}
		w.Header().Set("Allow", allow)
		fail(w, 405, "method_not_allowed", "Read with GET; preview or change a named case with PUT.")
		return true
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		fail(w, 400, "invalid_hold_query", "Use valid URL-encoded query parameters.")
		return true
	}
	for k, v := range q {
		allowed := list && (k == "state" || k == "repository" || k == "path" || k == "case_id" || k == "q" || k == "limit" || k == "cursor") || item && (k == "path" || history && (k == "limit" || k == "cursor"))
		if !allowed || len(v) != 1 {
			fail(w, 400, "invalid_hold_query", "Supply one value for each documented hold-case query field.")
			return true
		}
	}
	if item && !history {
		value, e := s.DB.HoldCase(r.Context(), i, bits[1], q.Get("path"), bits[4])
		if e != nil {
			respondErr(w, e)
		} else {
			writeJSON(w, 200, value)
		}
		return true
	}
	req := store.HoldCaseListRequest{ListRequest: store.ListRequest{Limit: 100, MetadataBytes: s.ManagementMetadataBytes, Query: q.Get("q")}, State: q.Get("state"), Repository: q.Get("repository"), Path: q.Get("path"), CaseID: q.Get("case_id")}
	if req.State == "" {
		req.State = "active"
	}
	if history {
		req.Repository = bits[1]
		req.CaseID = bits[4]
		req.State = ""
	}
	if v := q.Get("limit"); v != "" {
		req.Limit, e = strconv.Atoi(v)
	}
	if e != nil || req.Validate() != nil {
		fail(w, 400, "invalid_hold_query", "Use a page limit from 1 to 100, valid filters and a bounded literal search.")
		return true
	}
	if history && (!ValidPath(req.Path) || len(req.Path) > 2048) {
		fail(w, 400, "invalid_hold_query", "Supply one canonical OCI digest path.")
		return true
	}
	kind := "hold-case-inventory-v1"
	if history {
		kind = "hold-case-history-v1"
	}
	scopeBytes, _ := json.Marshal([]string{kind, i.Tenant, i.Actor, i.Role, i.CredentialHash, req.Repository, req.Path, req.CaseID, req.State, req.Query})
	scope := string(scopeBytes)
	if s.PaginationKey == nil {
		fail(w, 503, "pagination_key_unavailable", "Configure the private pagination key and retry.")
		return true
	}
	if cursor := q.Get("cursor"); cursor != "" {
		req.Key, req.Before, e = s.PaginationKey.Open(scope, cursor)
		if e != nil || req.Validate() != nil {
			fail(w, 400, "invalid_cursor", "Restart with the same endpoint, filters and current credential.")
			return true
		}
	}
	var items any
	var window store.ListWindow
	result := map[string]any{}
	if history {
		items, window, e = s.DB.HoldCaseHistory(r.Context(), i, req.Repository, req.Path, req.CaseID, req.ListRequest)
	} else {
		var observed any
		values, w, at, err := s.DB.HoldCasePage(r.Context(), i, req)
		items, window, e, observed = values, w, err, at
		result["observed_at"] = observed
	}
	if e != nil {
		if errors.Is(e, store.ErrMetadataLimit) {
			fail(w, 503, "hold_page_budget_exceeded", "Reduce the page size or inspect the management metadata byte budget. No partial record was returned.")
		} else {
			respondErr(w, e)
		}
		return true
	}
	next, previous, e := s.holdPageCursors(scope, req.ListRequest, window)
	if e != nil {
		fail(w, 503, "pagination_cursor_failed", "Restart the list or inspect pagination configuration.")
		return true
	}
	result["items"], result["limit"], result["next"], result["previous"] = items, req.Limit, next, previous
	result["scope"] = "Live tenant-administrator page. Each case preserves its own revision and original receipts. Other cases and the legacy hold remain independent. Expiry and concurrent changes can alter traversal; restart for earlier insertions."
	writeJSON(w, 200, result)
	return true
}
func (s *Server) putHoldCase(w http.ResponseWriter, r *http.Request, i store.Identity, repo, id string) {
	if r.URL.RawQuery != "" {
		fail(w, 400, "invalid_query", "Send hold-case mutation parameters in the JSON body.")
		return
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if e != nil {
		fail(w, 413, "request_limit", "Limit hold-case JSON to 16 KiB.")
		return
	}
	var input store.HoldCaseRequest
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields["expected_revision"] == nil || string(fields["expected_revision"]) == "null" {
		fail(w, 400, "revision_required", "Read this case and supply its expected_revision explicitly, or zero for a new case.")
		return
	}
	if !decodeManagement(data, &input) {
		fail(w, 400, "invalid_hold_case_request", "Use a documented action, exact digest, case revision and bounded reason.")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !input.DryRun && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key; retry only the identical request.")
		return
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	result, e := s.DB.ChangeHoldCase(r.Context(), i, repo, id, key, fp, input)
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, result)
	}
}
