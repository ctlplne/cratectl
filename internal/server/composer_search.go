// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/store"
)

type composerSearchResult struct {
	store.ComposerSearchHit
	URL string `json:"url"`
}

type composerSearchQuery struct {
	text    string
	pattern string
	empty   bool
}

func parseComposerSearch(raw string, list bool) (composerSearchQuery, bool) {
	if len(raw) > 1024 {
		return composerSearchQuery{}, false
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return composerSearchQuery{}, false
	}
	for key, values := range query {
		known := list && key == "filter" || !list && (key == "q" || key == "type")
		if !known || len(values) != 1 || !utf8.ValidString(values[0]) || strings.ContainsFunc(values[0], unicode.IsControl) {
			return composerSearchQuery{}, false
		}
	}
	if list {
		filter := strings.ToLower(query.Get("filter"))
		if len(filter) > 214 || strings.Count(filter, "*") > 16 || strings.ContainsFunc(filter, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '/' || r == '-' || r == '_' || r == '.' || r == '*')
		}) {
			return composerSearchQuery{}, false
		}
		if filter == "" {
			filter = "*"
		}
		pattern := strings.NewReplacer("_", `\_`, "*", "%").Replace(filter)
		return composerSearchQuery{pattern: pattern}, true
	}
	term := strings.Join(strings.Fields(query.Get("q")), " ")
	if term == "" || len(term) > 256 || len(strings.Fields(term)) > 16 {
		return composerSearchQuery{}, false
	}
	kind := query.Get("type")
	if kind != "" && kind != "library" {
		return composerSearchQuery{empty: true}, true
	}
	return composerSearchQuery{text: term}, true
}

func (s *Server) serveComposerSearch(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, list bool) {
	if repo.Mode != "hosted" {
		respondErr(w, store.ErrNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Read Composer discovery with GET or HEAD.")
		return
	}
	query, valid := parseComposerSearch(r.URL.RawQuery, list)
	if !valid {
		fail(w, 400, "invalid_composer_search", "Use one bounded Composer text query or one package-name filter.")
		return
	}
	hits := []store.ComposerSearchHit{}
	if !query.empty {
		var err error
		hits, err = s.DB.ComposerSearch(r.Context(), i, repo.Name, query.text, query.pattern, s.NativeVersionLimit, s.NativeMetadataBytes)
		if err != nil {
			respondErr(w, err)
			return
		}
	}
	var reply any
	if list {
		names := make([]string, 0, len(hits))
		for _, hit := range hits {
			names = append(names, hit.Name)
		}
		reply = map[string][]string{"packageNames": names}
	} else {
		results := make([]composerSearchResult, 0, min(100, len(hits)))
		for _, hit := range hits[:min(100, len(hits))] {
			results = append(results, composerSearchResult{ComposerSearchHit: hit, URL: s.PublicURL + "/composer/" + repo.Name + "/p2/" + hit.Name + ".json"})
		}
		reply = struct {
			Results []composerSearchResult `json:"results"`
			Total   int                    `json:"total"`
		}{Results: results, Total: len(hits)}
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		respondErr(w, err)
		return
	}
	if int64(len(raw)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	serveComposerJSON(w, r, raw)
}
