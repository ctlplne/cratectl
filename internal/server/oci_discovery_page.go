// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

type ociPage struct {
	Size int
	Last string
}

func parseOCIPage(raw, kind string, maximum int) (ociPage, error) {
	page := ociPage{Size: maximum}
	values, e := url.ParseQuery(raw)
	if e != nil || maximum <= 0 || len(values["n"]) > 1 || len(values["last"]) > 1 {
		return page, errors.New("invalid OCI pagination")
	}
	if n, exists := values["n"]; exists {
		value, e := strconv.ParseUint(n[0], 10, 31)
		if e != nil {
			return page, errors.New("invalid OCI page size")
		}
		page.Size = min(int(value), maximum)
	}
	if last, exists := values["last"]; exists {
		page.Last = last[0]
		if kind == "tags/list" && !ociTag.MatchString(page.Last) || kind == "referrers" && !ociDigest.MatchString(page.Last) {
			return page, errors.New("invalid OCI page marker")
		}
	}
	return page, nil
}
func (p ociPage) bounds(count int, after func(int) bool) (int, int) {
	start := 0
	if p.Last != "" {
		for start < count && !after(start) {
			start++
		}
	}
	return start, min(count, start+p.Size)
}
func (s *Server) serveOCIDiscoveryPage(w http.ResponseWriter, r *http.Request, repo store.Repository, image, kind, ref, filter string, i store.Identity) {
	page, e := parseOCIPage(r.URL.RawQuery, kind, s.OCIPageSize)
	if e != nil {
		fail(w, 400, "PAGINATION_INVALID", "Use one nonnegative n and one valid last tag/digest; follow the returned next Link.")
		return
	}
	tags, refs, e := s.ociDiscovery(r.Context(), i, repo, image, kind, ref, filter, forceRefresh(r))
	if e != nil {
		respondErr(w, e)
		return
	}
	var data []byte
	next := ""
	if kind == "tags/list" {
		start, end := page.bounds(len(tags), func(n int) bool { return store.CompareOCITags(tags[n], page.Last) > 0 })
		data, _ = json.Marshal(map[string]any{"name": repo.Name + "/" + image, "tags": tags[start:end]})
		if page.Size > 0 && end < len(tags) {
			next = tags[end-1]
		}
		w.Header().Set("Content-Type", "application/json")
	} else {
		start, end := page.bounds(len(refs), func(n int) bool { return refs[n].Digest > page.Last })
		data, _ = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociIndexMediaType, "manifests": refs[start:end]})
		if page.Size > 0 && end < len(refs) {
			next = refs[end-1].Digest
		}
		if filter != "" {
			w.Header().Set("OCI-Filters-Applied", "artifactType")
		}
		w.Header().Set("Content-Type", ociIndexMediaType)
	}
	if int64(len(data)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	if next != "" {
		values := url.Values{"n": {strconv.Itoa(page.Size)}, "last": {next}}
		if filter != "" {
			values.Set("artifactType", filter)
		}
		target := url.URL{Path: r.URL.Path, RawQuery: values.Encode()}
		w.Header().Set("Link", "<"+target.String()+">; rel=\"next\"")
	}
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(data)+`"`)
	http.ServeContent(w, r, "oci-discovery.json", time.Time{}, bytes.NewReader(data))
}
