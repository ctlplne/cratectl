// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) configurationManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	bits := strings.Split(p, "/")
	if len(bits) < 3 || len(bits) > 4 || bits[0] != "repositories" || bits[2] != "configuration" {
		return false
	}
	if !store.Name.MatchString(bits[1]) {
		respondErr(w, store.ErrConfigurationInput)
		return true
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	repo := bits[1]
	if len(bits) == 4 {
		if bits[3] != "history" || r.Method != "GET" {
			fail(w, 404, "not_found", "Use GET on configuration/history.")
			return true
		}
		q := r.URL.Query()
		after := int64(0)
		limit := 10
		var e error
		if len(q) > 2 || len(q["after"]) > 1 || len(q["limit"]) > 1 {
			respondErr(w, store.ErrConfigurationInput)
			return true
		}
		for key := range q {
			if key != "after" && key != "limit" {
				respondErr(w, store.ErrConfigurationInput)
				return true
			}
		}
		if q.Get("after") != "" {
			after, e = strconv.ParseInt(q.Get("after"), 10, 64)
			if e != nil {
				respondErr(w, store.ErrConfigurationInput)
				return true
			}
		}
		if q.Get("limit") != "" {
			limit, e = strconv.Atoi(q.Get("limit"))
			if e != nil {
				respondErr(w, store.ErrConfigurationInput)
				return true
			}
		}
		rows, e := s.DB.ConfigurationHistory(r.Context(), i, repo, after, limit)
		if e != nil {
			respondErr(w, e)
		} else {
			next := after
			if len(rows) > 0 {
				next = rows[len(rows)-1].Revision
			}
			writeJSON(w, 200, map[string]any{"items": rows, "after": next, "limit": limit})
		}
		return true
	}
	if r.URL.RawQuery != "" {
		respondErr(w, store.ErrConfigurationInput)
		return true
	}
	if r.Method == "GET" {
		value, e := s.DB.Configuration(r.Context(), i, repo)
		if e != nil {
			respondErr(w, e)
		} else {
			writeJSON(w, 200, value)
		}
		return true
	}
	if r.Method != "PUT" {
		w.Header().Set("Allow", "GET, PUT")
		fail(w, 405, "method_not_allowed", "Read configuration with GET; preview or replace settings with PUT.")
		return true
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		fail(w, 413, "request_limit", "Limit repository configuration JSON to 64 KiB.")
		return true
	}
	var input store.ConfigurationRequest
	var fields map[string]json.RawMessage
	if !decodeManagement(data, &input) || json.Unmarshal(data, &fields) != nil || fields["expected_revision"] == nil || string(fields["expected_revision"]) == "null" || input.Settings == nil {
		respondErr(w, store.ErrConfigurationInput)
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !input.DryRun && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key; retry it only with identical request bytes.")
		return true
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	if !input.DryRun {
		prior, found, e := s.DB.ReplayMutation(r.Context(), i, key, fp)
		if e != nil {
			respondErr(w, e)
			return true
		}
		if found {
			writeLifecycleResult(w, prior)
			return true
		}
	}
	if e = s.validateConfigurationCredentials(i, *input.Settings); e != nil {
		fail(w, 400, "upstream_credential_authority", "Configure every credential reference for its exact approved upstream, download or token authority before applying these settings.")
		return true
	}
	result, e := s.DB.ChangeConfiguration(r.Context(), i, repo, key, fp, input, s.NativeVersionLimit)
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, result)
	}
	return true
}
func (s *Server) validateConfigurationCredentials(i store.Identity, settings store.RepositorySettings) error {
	if settings.GoChecksumAuthority != nil {
		if _, e := s.credential(i.Tenant, settings.GoChecksumAuthority.Endpoint); e != nil {
			return e
		}
	}
	if settings.Upstream != nil {
		if _, e := s.credential(i.Tenant, *settings.Upstream); e != nil {
			return e
		}
	}
	for _, source := range settings.DownloadSources {
		if _, e := s.credential(i.Tenant, source); e != nil {
			return e
		}
	}
	if settings.OCITokenEndpoint != nil {
		if _, e := s.credential(i.Tenant, *settings.OCITokenEndpoint); e != nil {
			return e
		}
	}
	return nil
}
