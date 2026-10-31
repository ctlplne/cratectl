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

func readRetentionBody(w http.ResponseWriter, r *http.Request, target any, fields ...string) ([]byte, bool) {
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if e != nil {
		fail(w, 413, "request_limit", "Limit retention JSON to 16 KiB.")
		return nil, false
	}
	if !utf8.Valid(data) || uniqueOCIJSON(data) != nil || !decodeManagement(data, target) {
		fail(w, 400, "invalid_retention", "Send one JSON object with documented retention fields and no duplicate properties.")
		return nil, false
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(data, &values) != nil {
		respondErr(w, store.ErrRetentionInput)
		return nil, false
	}
	for _, field := range fields {
		if values[field] == nil || string(values[field]) == "null" {
			fail(w, 400, "retention_field_required", "Supply every required policy field explicitly, including expected_revision and tag protection.")
			return nil, false
		}
	}
	return data, true
}
func retentionPage(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	query, e := retentionQuery(r)
	if e != nil {
		fail(w, 400, "invalid_query", "Use one after cursor and one limit from 1 to 100.")
		return "", 0, false
	}
	limit := 100
	if query["limit"] != "" {
		limit, e = strconv.Atoi(query["limit"])
	}
	if e != nil || limit < 1 || limit > 100 {
		respondErr(w, store.ErrRetentionInput)
		return "", 0, false
	}
	return query["after"], limit, true
}
func retentionQuery(r *http.Request) (map[string]string, error) {
	out := map[string]string{}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return out, e
	}
	for key, value := range query {
		if key != "limit" && key != "after" || len(value) != 1 {
			return out, store.ErrRetentionInput
		}
		out[key] = value[0]
	}
	return out, nil
}

func (s *Server) retentionManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	bits := strings.Split(p, "/")
	policies := len(bits) >= 3 && bits[0] == "repositories" && bits[2] == "retention-policies"
	runs := len(bits) >= 2 && bits[0] == "maintenance" && bits[1] == "retention-runs"
	if !policies && !runs {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if policies && (!store.Name.MatchString(bits[1]) || len(bits) > 5 || len(bits) >= 4 && !store.Name.MatchString(bits[3])) {
		respondErr(w, store.ErrRetentionInput)
		return true
	}
	if runs && (len(bits) < 3 || len(bits) > 4) {
		fail(w, 404, "not_found", "Choose a retention run and optionally its items endpoint.")
		return true
	}
	if r.Method == "GET" {
		after, limit, ok := retentionPage(w, r)
		if !ok {
			return true
		}
		numeric := func() (int64, error) {
			if after == "" {
				return 0, nil
			}
			n, e := strconv.ParseInt(after, 10, 64)
			if e != nil || n < 0 {
				return 0, store.ErrRetentionInput
			}
			return n, nil
		}
		if policies && len(bits) == 3 {
			items, more, e := s.DB.RetentionPolicies(r.Context(), i, bits[1], after, limit)
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, map[string]any{"items": items, "more": more})
			}
			return true
		}
		if policies && len(bits) == 4 {
			if r.URL.RawQuery != "" {
				respondErr(w, store.ErrRetentionInput)
				return true
			}
			out, e := s.DB.RetentionPolicy(r.Context(), i, bits[1], bits[3])
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, out)
			}
			return true
		}
		if policies && len(bits) == 5 {
			cursor, e := numeric()
			if e != nil {
				respondErr(w, e)
				return true
			}
			switch bits[4] {
			case "history":
				items, more, e := s.DB.RetentionHistory(r.Context(), i, bits[1], bits[3], cursor, limit)
				if e != nil {
					respondErr(w, e)
				} else {
					writeJSON(w, 200, map[string]any{"items": items, "more": more})
				}
			case "runs":
				items, more, e := s.DB.RetentionRuns(r.Context(), i, bits[1], bits[3], cursor, limit)
				if e != nil {
					respondErr(w, e)
				} else {
					writeJSON(w, 200, map[string]any{"items": items, "more": more})
				}
			default:
				fail(w, 404, "not_found", "Read policy history or runs.")
			}
			return true
		}
		if runs && len(bits) == 3 {
			if r.URL.RawQuery != "" {
				respondErr(w, store.ErrRetentionInput)
				return true
			}
			out, e := s.DB.RetentionRun(r.Context(), i, bits[2])
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, out)
			}
			return true
		}
		if runs && len(bits) == 4 && bits[3] == "items" {
			cursor, e := numeric()
			if e != nil {
				respondErr(w, e)
				return true
			}
			items, more, e := s.DB.RetentionItems(r.Context(), i, bits[2], cursor, limit)
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, map[string]any{"items": items, "more": more, "bytes_reclaimed": 0})
			}
			return true
		}
		fail(w, 404, "not_found", "Choose a policy or retention run.")
		return true
	}
	policyWrite := policies && len(bits) == 4 && r.Method == "PUT"
	runWrite := policies && len(bits) == 5 && bits[4] == "runs" && r.Method == "POST"
	if !policyWrite && !runWrite {
		allow := "GET"
		if policies && len(bits) == 4 {
			allow = "GET, PUT"
		}
		if policies && len(bits) == 5 && bits[4] == "runs" {
			allow = "GET, POST"
		}
		w.Header().Set("Allow", allow)
		fail(w, 405, "method_not_allowed", "Read retention state with GET, replace a named policy with PUT, or preview/admit its run with POST.")
		return true
	}
	if r.URL.RawQuery != "" {
		respondErr(w, store.ErrRetentionInput)
		return true
	}
	var policy store.RetentionPolicyRequest
	var run store.RetentionRequest
	var data []byte
	var ok bool
	var dry bool
	if policyWrite {
		data, ok = readRetentionBody(w, r, &policy, "expected_revision", "min_age_seconds", "keep_last", "protect_tagged", "enabled", "reason")
		dry = policy.DryRun
	} else {
		data, ok = readRetentionBody(w, r, &run, "expected_revision", "reason")
		dry = run.DryRun
	}
	if !ok {
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !dry && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key and reuse it only for an identical request.")
		return true
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	var result store.Result
	var e error
	if policyWrite {
		result, e = s.DB.SetRetentionPolicy(r.Context(), i, bits[1], bits[3], key, fp, policy)
	} else {
		result, e = s.DB.StartRetention(r.Context(), i, bits[1], bits[3], key, fp, run, min(s.NativeVersionLimit, 10000))
	}
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, result)
	}
	return true
}
