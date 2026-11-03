// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) nugetCatalogManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	bits := strings.Split(p, "/")
	if len(bits) != 4 || bits[0] != "repositories" || bits[2] != "nuget" || bits[3] != "reindex" {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if !store.Name.MatchString(bits[1]) || r.URL.RawQuery != "" {
		respondErr(w, store.ErrConfigurationInput)
		return true
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "method_not_allowed", "Preview or rebuild a bounded NuGet catalog batch with POST.")
		return true
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		fail(w, 413, "request_limit", "Limit this rebuild request to 8 KiB.")
		return true
	}
	var input store.NuGetReindexRequest
	if !decodeManagement(data, &input) {
		respondErr(w, store.ErrConfigurationInput)
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !input.DryRun && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key and reuse it only for the identical batch request.")
		return true
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, e := s.DB.RebuildNuGetCatalog(ctx, i, bits[1], key, fp, input, s.NativeMetadataBytes)
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, result)
	}
	return true
}
