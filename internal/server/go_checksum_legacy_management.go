// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
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

type legacyChecksumReviewInput struct {
	Repository string `json:"repository"`
	store.GoChecksumLegacyReviewRequest
}

// Review intent is flat JSON. Refuse duplicate, missing and null bindings before
// resolving current trust. Whitespace does not affect the typed request, while
// the exact original bytes remain the durable idempotency fingerprint.
func decodeLegacyChecksumReview(raw []byte) (legacyChecksumReviewInput, bool) {
	var out legacyChecksumReviewInput
	if len(raw) > 64<<10 || !utf8.Valid(raw) {
		return out, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, false
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return out, false
		}
		name, ok := token.(string)
		if !ok {
			return out, false
		}
		switch name {
		case "repository", "dry_run", "accept_unattributed_history", "incident_hash", "expected_source_revision", "key_digest", "expected_checkpoint_revision", "checkpoint_sha256", "review_reference_sha256", "reason":
		default:
			return out, false
		}
		if _, exists := fields[name]; exists {
			return out, false
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return out, false
		}
		fields[name] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return out, false
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return out, false
	}
	for _, name := range []string{"repository", "dry_run", "incident_hash", "expected_source_revision", "key_digest", "expected_checkpoint_revision", "checkpoint_sha256", "review_reference_sha256", "reason"} {
		v, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return out, false
		}
	}
	if !decodeManagement(raw, &out) {
		return legacyChecksumReviewInput{}, false
	}
	return out, true
}

func legacyChecksumQuery(raw string) (url.Values, bool) {
	if len(raw) > 8192 {
		return nil, false
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, false
	}
	for k, v := range q {
		if k != "after" && k != "limit" && k != "key_digest" || len(v) != 1 || v[0] == "" {
			return nil, false
		}
	}
	return q, true
}

func legacyChecksumInteger(value string, fallback int64) (int64, bool) {
	if value == "" {
		return fallback, true
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && n >= 0 && strconv.FormatInt(n, 10) == value
}

func (s *Server) goChecksumLegacyManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) bool {
	p := strings.Split(path, "/")
	if len(p) < 3 || len(p) > 5 || p[0] != "go" || p[1] != "checksum" || p[2] != "legacy-incidents" || len(p) == 5 && p[4] != "reviews" {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if len(p) == 3 {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			fail(w, 405, "method_not_allowed", "Inspect retained unattributed incidents with GET.")
			return true
		}
		q, ok := legacyChecksumQuery(r.URL.RawQuery)
		after, a := legacyChecksumInteger(q.Get("after"), 0)
		limit, b := legacyChecksumInteger(q.Get("limit"), 25)
		if !ok || !a || !b || limit < 1 || limit > 100 {
			respondErr(w, store.ErrGoChecksumLegacyInput)
			return true
		}
		items, more, err := s.DB.GoChecksumLegacyIncidentPage(r.Context(), i, after, int(limit), q.Get("key_digest"))
		if err != nil {
			respondErr(w, err)
			return true
		}
		next := int64(0)
		if more {
			next = items[len(items)-1].Sequence
		}
		writeJSON(w, 200, map[string]any{"items": items, "more": more, "next_after": next, "limit": limit, "key_digest": q.Get("key_digest"), "classification": "unattributed_fork_label", "package_admission": false})
		return true
	}
	sequence, valid := legacyChecksumInteger(p[3], -1)
	if !valid || sequence <= 0 || r.URL.RawQuery != "" && !(len(p) == 5 && r.Method == "GET") {
		respondErr(w, store.ErrGoChecksumLegacyInput)
		return true
	}
	if len(p) == 4 {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			fail(w, 405, "method_not_allowed", "Read the original incident journal with GET.")
			return true
		}
		out, err := s.DB.GoChecksumLegacyIncidentEvidence(r.Context(), i, sequence)
		if err != nil {
			respondErr(w, err)
		} else {
			writeJSON(w, 200, out)
		}
		return true
	}
	if r.Method == "GET" {
		q, ok := legacyChecksumQuery(r.URL.RawQuery)
		if !ok || len(q) != 1 || q.Get("key_digest") == "" {
			respondErr(w, store.ErrGoChecksumLegacyInput)
			return true
		}
		out, err := s.DB.GoChecksumLegacyReviewEvidence(r.Context(), i, sequence, q.Get("key_digest"))
		if err != nil {
			respondErr(w, err)
		} else {
			writeJSON(w, 200, out)
		}
		return true
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		fail(w, 405, "method_not_allowed", "Preview or record explicit external-trust review with POST; supply dry_run and exact reviewed bindings.")
		return true
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		fail(w, 413, "request_limit", "Limit checksum incident review JSON to 64 KiB.")
		return true
	}
	input, ok := decodeLegacyChecksumReview(raw)
	if !ok {
		respondErr(w, store.ErrGoChecksumLegacyInput)
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !input.DryRun && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an Idempotency-Key containing 8–128 characters; repeat it only with identical review bytes.")
		return true
	}
	fingerprint := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), raw...))
	result, err := s.DB.ReviewGoChecksumLegacyIncident(r.Context(), i, input.Repository, sequence, key, fingerprint, input.GoChecksumLegacyReviewRequest)
	if err != nil {
		respondErr(w, err)
	} else {
		writeLifecycleResult(w, result)
	}
	return true
}
