// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) managementPage(w http.ResponseWriter, r *http.Request, i store.Identity, repo string) {
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		fail(w, 400, "invalid_pagination", "Use a valid URL-encoded query.")
		return
	}
	for key, vs := range query {
		if len(vs) != 1 || (key != "cursor" && key != "limit" && key != "q" && (key != "metadata" || repo == "")) {
			fail(w, 400, "invalid_pagination", "Use one limit, q, metadata and returned cursor value.")
			return
		}
	}
	req := store.ListRequest{MetadataBytes: s.ManagementMetadataBytes, Limit: 1000, Query: query.Get("q"), Summary: query.Get("metadata") == "omit"}
	if v := query.Get("limit"); v != "" {
		req.Limit, e = strconv.Atoi(v)
	}
	if e != nil || req.Validate() != nil || query.Get("metadata") != "" && query.Get("metadata") != "omit" {
		fail(w, 400, "invalid_pagination", "Use limit 1–1000, q up to 256 UTF-8 bytes, and metadata=omit for a summary.")
		return
	}
	if s.PaginationKey == nil {
		fail(w, 503, "pagination_key_unavailable", "Configure a private pagination key and retry.")
		return
	}
	scopeBytes, _ := json.Marshal([]string{"management-v1", i.Tenant, i.Actor, i.Role, i.CredentialHash, repo, req.Query, strconv.FormatBool(req.Summary)})
	scope := string(scopeBytes)
	if cursor := query.Get("cursor"); cursor != "" {
		req.Key, req.Before, e = s.PaginationKey.Open(scope, cursor)
		if e != nil {
			fail(w, 400, "invalid_cursor", "Restart at the first page with the current credential and filters.")
			return
		}
	}
	var items any
	var window store.ListWindow
	if repo == "" {
		items, window, e = s.DB.RepositoryPage(r.Context(), i, req)
	} else {
		items, window, e = s.DB.ArtifactPage(r.Context(), i, repo, "", req, true)
	}
	if e != nil {
		managementPageError(w, e)
		return
	}
	next, previous := "", ""
	if req.Before {
		if window.More {
			previous, e = s.PaginationKey.Seal(scope, window.First, true)
			if e != nil {
				fail(w, 503, "pagination_cursor_failed", "Inspect unsupported list keys and restart the list.")
				return
			}
		}
		key := window.Last
		if key == "" {
			key = req.Key
		}
		if req.Key != "" {
			next, e = s.PaginationKey.Seal(scope, key, false)
		}
	} else {
		if window.More {
			next, e = s.PaginationKey.Seal(scope, window.Last, false)
			if e != nil {
				fail(w, 503, "pagination_cursor_failed", "Inspect unsupported list keys and restart the list.")
				return
			}
		}
		key := window.First
		if key == "" {
			key = req.Key
		}
		if req.Key != "" {
			previous, e = s.PaginationKey.Seal(scope, key, true)
		}
	}
	if e != nil {
		fail(w, 503, "pagination_cursor_failed", "Restart the list or inspect private pagination configuration.")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "limit": req.Limit, "next": next, "previous": previous, "scope": "Live page. Current grants and policy apply; concurrent changes can alter traversal. Restart at the first page to see insertions before the cursor."})
}
func (s *Server) managementReference(w http.ResponseWriter, r *http.Request, i store.Identity, p string) {
	values, parseError := url.ParseQuery(r.URL.RawQuery)
	if parseError != nil || len(values) != 1 || len(values["path"]) != 1 || !ValidPath(values.Get("path")) {
		fail(w, 400, "invalid_path", "Choose one canonical artifact path.")
		return
	}
	repo := strings.TrimSuffix(strings.TrimPrefix(p, "repositories/"), "/artifacts/reference")
	value, e := s.DB.ArtifactReference(r.Context(), i, repo, values.Get("path"), s.ManagementMetadataBytes)
	if e != nil {
		managementPageError(w, e)
		return
	}
	writeJSON(w, 200, value)
}

func managementPageError(w http.ResponseWriter, e error) {
	if errors.Is(e, store.ErrMetadataLimit) {
		fail(w, 503, "metadata_budget_exceeded", "Use metadata=omit to traverse reference summaries, or ask the operator to inspect management-metadata-bytes and OCI graph work budgets. No partial record was returned.")
		return
	}
	respondErr(w, e)
}
