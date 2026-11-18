// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/store"
)

type npmSearchObject struct {
	Package store.NPMSearchPackage `json:"package"`
}

func (s *Server) npmSearch(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET or HEAD for npm search.")
		return
	}
	text, from, size, ok := npmSearchQuery(r.URL.RawQuery)
	if !ok {
		fail(w, http.StatusBadRequest, "invalid_npm_search", "Use bounded search text, size and offset.")
		return
	}
	results, total, err := s.DB.NPMSearch(r.Context(), i, repo.Name, text, from, size, min(s.NativeVersionLimit, 10000),
		s.NativeTagLimit, s.NativeMetadataBytes)
	if err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return
	}
	objects := make([]npmSearchObject, 0, len(results))
	for _, hit := range results {
		objects = append(objects, npmSearchObject{Package: hit})
	}
	writeJSON(w, http.StatusOK, struct {
		Objects []npmSearchObject `json:"objects"`
		Total   int               `json:"total"`
	}{objects, total})
}

func npmSearchQuery(raw string) (string, int, int, bool) {
	if len(raw) > 2048 {
		return "", 0, 0, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values["text"]) != 1 {
		return "", 0, 0, false
	}
	text := values.Get("text")
	if len(text) > 256 || !utf8.ValidString(text) || strings.IndexFunc(text, unicode.IsControl) >= 0 {
		return "", 0, 0, false
	}
	terms := strings.Fields(text)
	if len(terms) < 1 || len(terms) > 16 {
		return "", 0, 0, false
	}
	from, ok := npmSearchNumber(values["from"], 0, 10000)
	size, sizeOK := npmSearchNumber(values["size"], 20, 100)
	return text, from, size, ok && sizeOK
}

func npmSearchNumber(values []string, fallback, maximum int) (int, bool) {
	if len(values) == 0 {
		return fallback, true
	}
	if len(values) != 1 {
		return 0, false
	}
	n, err := strconv.Atoi(values[0])
	return n, err == nil && n >= 0 && n <= maximum
}
