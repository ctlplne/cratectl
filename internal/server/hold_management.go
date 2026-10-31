// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) holdManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	bits := strings.Split(p, "/")
	list := p == "holds"
	history := len(bits) == 5 && bits[0] == "repositories" && bits[2] == "artifacts" && bits[3] == "lifecycle" && bits[4] == "history"
	if !list && !history {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Read hold inventory and immutable receipts with GET.")
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400, "invalid_hold_query", "Use a valid URL-encoded hold query.")
		return true
	}
	for key, values := range query {
		allowed := key == "cursor" || key == "limit" || list && (key == "state" || key == "repository" || key == "q") || history && key == "path"
		if !allowed || len(values) != 1 {
			fail(w, 400, "invalid_hold_query", "Use one value for each documented hold query field.")
			return true
		}
	}
	req := store.ListRequest{Limit: 100, MetadataBytes: s.ManagementMetadataBytes, Query: query.Get("q")}
	if value := query.Get("limit"); value != "" {
		req.Limit, err = strconv.Atoi(value)
	}
	if err != nil || req.Validate() != nil || req.Limit > 100 {
		fail(w, 400, "invalid_hold_query", "Use a page limit from 1 to 100 and a bounded literal search.")
		return true
	}
	state, repo, path := query.Get("state"), query.Get("repository"), query.Get("path")
	kind := "hold-inventory-v1"
	if list {
		if state == "" {
			state = "active"
		}
	} else {
		kind = "hold-history-v1"
		repo = bits[1]
		if !store.Name.MatchString(repo) || !ValidPath(path) || len(path) > 2048 {
			fail(w, 400, "invalid_hold_query", "Supply one repository and canonical OCI digest path.")
			return true
		}
	}
	scopeBytes, _ := json.Marshal([]string{kind, i.Tenant, i.Actor, i.Role, i.CredentialHash, repo, path, state, req.Query})
	scope := string(scopeBytes)
	if s.PaginationKey == nil {
		fail(w, 503, "pagination_key_unavailable", "Configure the private pagination key and retry.")
		return true
	}
	if cursor := query.Get("cursor"); cursor != "" {
		req.Key, req.Before, err = s.PaginationKey.Open(scope, cursor)
		if err != nil {
			fail(w, 400, "invalid_cursor", "Restart with the current credential and the same endpoint and filters.")
			return true
		}
	}
	var items any
	var window store.ListWindow
	var observed time.Time
	if list {
		request := store.HoldListRequest{ListRequest: req, State: state, Repository: repo}
		if request.Validate() != nil {
			fail(w, 400, "invalid_hold_query", "Use a documented hold state, repository and bounded position.")
			return true
		}
		items, window, observed, err = s.DB.HoldPage(r.Context(), i, request)
	} else {
		if req.Validate() != nil {
			fail(w, 400, "invalid_hold_query", "Restart the hold history at its first page.")
			return true
		}
		if req.Key != "" {
			n, e := strconv.ParseInt(req.Key, 10, 64)
			if e != nil || n < 0 {
				fail(w, 400, "invalid_cursor", "Restart the hold history at its first page.")
				return true
			}
		}
		items, window, err = s.DB.HoldHistory(r.Context(), i, repo, path, req)
	}
	if err != nil {
		if errors.Is(err, store.ErrMetadataLimit) {
			fail(w, 503, "hold_page_budget_exceeded", "Reduce the page size or inspect the configured management metadata byte budget. No partial record was returned.")
		} else {
			respondErr(w, err)
		}
		return true
	}
	next, previous, err := s.holdPageCursors(scope, req, window)
	if err != nil {
		fail(w, 503, "pagination_cursor_failed", "Restart the hold list or inspect private pagination configuration.")
		return true
	}
	result := map[string]any{"items": items, "limit": req.Limit, "next": next, "previous": previous, "scope": "Live tenant-administrator page. Current authority applies on each request; concurrent changes and expiry can alter traversal. Historical receipt snapshots keep their original meaning. Restart the first page for earlier insertions."}
	if list {
		result["observed_at"] = observed
	}
	writeJSON(w, 200, result)
	return true
}
func (s *Server) holdPageCursors(scope string, req store.ListRequest, window store.ListWindow) (string, string, error) {
	next, previous := "", ""
	var err error
	if req.Before {
		if window.More {
			previous, err = s.PaginationKey.Seal(scope, window.First, true)
			if err != nil {
				return "", "", err
			}
		}
		key := window.Last
		if key == "" {
			key = req.Key
		}
		if req.Key != "" {
			next, err = s.PaginationKey.Seal(scope, key, false)
		}
	} else {
		if window.More {
			next, err = s.PaginationKey.Seal(scope, window.Last, false)
			if err != nil {
				return "", "", err
			}
		}
		key := window.First
		if key == "" {
			key = req.Key
		}
		if req.Key != "" {
			previous, err = s.PaginationKey.Seal(scope, key, true)
		}
	}
	return next, previous, err
}
