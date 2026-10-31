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
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func readMatterBody(w http.ResponseWriter, r *http.Request, target any, maximum int, fields ...string) ([]byte, bool) {
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(maximum)))
	if e != nil {
		fail(w, 413, "request_limit", "Keep the complete hold-matter request within the configured metadata budget.")
		return nil, false
	}
	if !utf8.Valid(data) || uniqueOCIJSON(data) != nil || !decodeManagement(data, target) {
		fail(w, 400, "invalid_hold_matter", "Send one JSON object with documented fields and no duplicate properties.")
		return nil, false
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(data, &values) != nil {
		respondErr(w, store.ErrMatterInput)
		return nil, false
	}
	for _, field := range fields {
		if values[field] == nil || string(values[field]) == "null" {
			fail(w, 400, "hold_matter_field_required", "Supply every required review field explicitly, including the exact revision and target manifest.")
			return nil, false
		}
	}
	return data, true
}
func (s *Server) holdMatterManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	if p != "hold-matters" && !strings.HasPrefix(p, "hold-matters/") {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	bits := strings.Split(p, "/")
	name := ""
	if len(bits) > 1 {
		name = bits[1]
		if !store.Name.MatchString(name) {
			respondErr(w, store.ErrMatterInput)
			return true
		}
	}
	root := len(bits) == 1
	entity := len(bits) == 2
	members := len(bits) == 3 && bits[2] == "members"
	history := len(bits) == 3 && bits[2] == "history"
	operations := len(bits) == 3 && bits[2] == "operations"
	preview := len(bits) == 4 && bits[2] == "operations" && bits[3] == "preview"
	detail := false
	items := false
	review := ""
	var sequence int64
	var e error
	if (len(bits) == 4 || len(bits) == 5) && bits[2] == "operations" && !preview {
		sequence, e = strconv.ParseInt(bits[3], 10, 64)
		if e != nil || sequence < 1 || strconv.FormatInt(sequence, 10) != bits[3] {
			respondErr(w, store.ErrMatterInput)
			return true
		}
		detail = len(bits) == 4
		items = len(bits) == 5 && bits[4] == "items"
		if len(bits) == 5 && (bits[4] == "approve" || bits[4] == "cancel") {
			review = bits[4]
		}
	}
	if !root && !entity && !members && !history && !operations && !preview && !detail && !items && review == "" {
		fail(w, 404, "not_found", "Choose a documented matter, member, operation or history endpoint.")
		return true
	}
	budget := s.ManagementMetadataBytes
	if budget == 0 {
		budget = 8 << 20
	}
	limit := s.NativeVersionLimit
	if limit == 0 {
		limit = 4096
	}
	limit = min(limit, 10000)
	if r.Method == "PUT" && entity || r.Method == "POST" && (preview || operations || review != "") {
		if r.URL.RawQuery != "" {
			fail(w, 400, "invalid_query", "Send matter review parameters in the JSON body.")
			return true
		}
		var input store.HoldMatterRequest
		var request store.MatterPreviewRequest
		var plan store.MatterPlan
		var approval store.MatterApprovalRequest
		var data []byte
		var ok bool
		dry := false
		switch {
		case entity:
			data, ok = readMatterBody(w, r, &input, 16384, "expected_revision", "title", "reason", "state")
			dry = input.DryRun
		case preview:
			data, ok = readMatterBody(w, r, &request, min(budget, 8<<20), "action", "reason", "targets")
			dry = true
		case operations:
			data, ok = readMatterBody(w, r, &plan, min(budget, 8<<20), "matter", "action", "reason", "targets", "target_count", "evaluated_at", "expires_at", "requester", "preview_digest")
		default:
			data, ok = readMatterBody(w, r, &approval, 16384, "expected_revision", "preview_digest", "reason")
		}
		if !ok {
			return true
		}
		key := r.Header.Get("Idempotency-Key")
		if !dry && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
			fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key and reuse it only for the identical request.")
			return true
		}
		fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
		var result store.Result
		switch {
		case entity:
			result, e = s.DB.SetHoldMatter(r.Context(), i, name, key, fp, input)
		case preview:
			var p store.MatterPlan
			p, e = s.DB.PreviewMatterOperation(r.Context(), i, name, request, limit, budget)
			if e == nil {
				writeJSON(w, 200, p)
				return true
			}
		case operations:
			result, e = s.DB.StartMatterOperation(r.Context(), i, name, key, fp, plan, limit, budget)
		default:
			result, e = s.DB.ReviewMatterOperation(r.Context(), i, name, sequence, review, key, fp, approval)
		}
		if e != nil {
			respondErr(w, e)
		} else {
			writeLifecycleResult(w, result)
		}
		return true
	}
	if r.Method != "GET" || preview || review != "" {
		allow := "GET"
		if entity {
			allow = "GET, PUT"
		} else if operations {
			allow = "GET, POST"
		} else if preview || review != "" {
			allow = "POST"
		}
		w.Header().Set("Allow", allow)
		fail(w, 405, "method_not_allowed", "Read with GET; preview, admit or review with the documented mutation method.")
		return true
	}
	if entity || detail {
		if r.URL.RawQuery != "" {
			fail(w, 400, "invalid_query", "Read this exact record without query parameters.")
			return true
		}
		var value any
		if entity {
			value, e = s.DB.HoldMatter(r.Context(), i, name)
		} else {
			value, e = s.DB.MatterOperation(r.Context(), i, name, sequence)
		}
		if e != nil {
			respondErr(w, e)
		} else {
			writeJSON(w, 200, value)
		}
		return true
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		respondErr(w, store.ErrMatterInput)
		return true
	}
	for key, values := range query {
		allowed := key == "limit" || key == "cursor" || (root || members) && key == "q" || members && (key == "state" || key == "repository")
		if !allowed || len(values) != 1 {
			fail(w, 400, "invalid_query", "Supply one value for each documented matter-page filter.")
			return true
		}
	}
	req := store.ListRequest{Limit: 100, MetadataBytes: budget, Query: query.Get("q")}
	if v := query.Get("limit"); v != "" {
		req.Limit, e = strconv.Atoi(v)
	}
	if e != nil || req.Validate() != nil || req.Limit > 100 {
		respondErr(w, store.ErrMatterInput)
		return true
	}
	state, repo := query.Get("state"), query.Get("repository")
	if members && state == "" {
		state = "active"
	}
	kind := "matters"
	if members {
		kind = "matter-members"
	} else if operations {
		kind = "matter-operations"
	} else if history {
		kind = "matter-history"
	} else if items {
		kind = "matter-targets"
	}
	scopeBytes, _ := json.Marshal([]string{kind, i.Tenant, i.Actor, i.Role, i.CredentialHash, name, strconv.FormatInt(sequence, 10), state, repo, req.Query})
	scope := string(scopeBytes)
	if s.PaginationKey == nil {
		fail(w, 503, "pagination_key_unavailable", "Configure the private pagination key and retry.")
		return true
	}
	if cursor := query.Get("cursor"); cursor != "" {
		req.Key, req.Before, e = s.PaginationKey.Open(scope, cursor)
		if e != nil {
			fail(w, 400, "invalid_cursor", "Restart with the same endpoint, exact filters and current credential.")
			return true
		}
	}
	if root {
		if req.Validate() != nil || req.Key != "" && !store.Name.MatchString(req.Key) {
			respondErr(w, store.ErrMatterInput)
			return true
		}
	} else {
		if req.Key != "" {
			n, err := strconv.ParseInt(req.Key, 10, 64)
			if err != nil || n < 1 {
				fail(w, 400, "invalid_cursor", "Restart this matter page.")
				return true
			}
		}
	}
	var value any
	var window store.ListWindow
	result := map[string]any{}
	switch {
	case root:
		value, window, e = s.DB.MatterPage(r.Context(), i, req)
	case members:
		request := store.MatterMemberPageRequest{ListRequest: req, State: state, Repository: repo}
		if e = request.Validate(); e != nil {
			respondErr(w, e)
			return true
		}
		rows, w, observed, err := s.DB.MatterMembers(r.Context(), i, name, request)
		value, window, e = rows, w, err
		result["observed_at"] = observed
	case operations:
		value, window, e = s.DB.MatterOperations(r.Context(), i, name, req)
	case items:
		value, window, e = s.DB.MatterOperationItems(r.Context(), i, name, sequence, req)
	default:
		value, window, e = s.DB.MatterHistory(r.Context(), i, name, req)
	}
	if e != nil {
		if errors.Is(e, store.ErrMetadataLimit) {
			fail(w, 503, "matter_page_budget_exceeded", "Reduce page size or inspect the metadata budget. No partial record was returned.")
		} else {
			respondErr(w, e)
		}
		return true
	}
	next, previous, e := s.holdPageCursors(scope, req, window)
	if e != nil {
		fail(w, 503, "pagination_cursor_failed", "Restart the matter page or inspect pagination configuration.")
		return true
	}
	result["items"], result["limit"], result["next"], result["previous"] = value, req.Limit, next, previous
	result["scope"] = "Live administrator page; current authority and filters apply on every request. Historical receipts retain their original meaning. Restart to include earlier concurrent additions."
	writeJSON(w, 200, result)
	return true
}
