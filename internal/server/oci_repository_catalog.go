// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) serveOCIRepositoryCatalog(w http.ResponseWriter, r *http.Request, i store.Identity) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "List repositories with GET or HEAD.")
		return
	}
	if len(r.URL.RawQuery) > 1024 {
		fail(w, http.StatusBadRequest, "PAGINATION_INVALID", "Limit catalog pagination parameters to 1024 bytes.")
		return
	}
	page, err := parseOCIPage(r.URL.RawQuery, "_catalog", min(s.OCIPageSize, store.MaxOCIRepositoryPageSize))
	if err != nil {
		fail(w, http.StatusBadRequest, "PAGINATION_INVALID", "Use one nonnegative n and one valid last repository name.")
		return
	}
	names, next, err := s.DB.OCIRepositoryCatalog(r.Context(), i, page.Last, page.Size, s.NativeMetadataBytes)
	if err != nil {
		respondErr(w, err)
		return
	}
	data, _ := json.Marshal(map[string][]string{"repositories": names})
	if int64(len(data)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	if next != "" {
		values := url.Values{"n": {strconv.Itoa(page.Size)}, "last": {next}}
		target := url.URL{Path: r.URL.Path, RawQuery: values.Encode()}
		w.Header().Set("Link", "<"+target.String()+">; rel=\"next\"")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(data)+`"`)
	http.ServeContent(w, r, "oci-repositories.json", time.Time{}, bytes.NewReader(data))
}
