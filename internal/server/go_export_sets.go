// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"io"
	"net/http"

	"ctlplne.dev/cratectl/internal/store"
)

func decodeGoExportSet(raw []byte) (store.GoExportSetRequest, bool) {
	var input struct {
		Entries          []json.RawMessage `json:"entries"`
		LifetimeSeconds  int               `json:"lifetime_seconds"`
		MaxArtifactBytes int64             `json:"max_artifact_bytes"`
	}
	if !decodeBoundedGoExport(raw, store.MaxGoExportSetRequest, &input, "entries", "lifetime_seconds", "max_artifact_bytes") || len(input.Entries) < 1 || len(input.Entries) > store.MaxGoExportSetEntries {
		return store.GoExportSetRequest{}, false
	}
	request := store.GoExportSetRequest{LifetimeSeconds: input.LifetimeSeconds, MaxArtifactBytes: input.MaxArtifactBytes}
	for _, entry := range input.Entries {
		var member store.GoExportSetEntry
		if !decodeGoExport(entry, &member, "repository", "module", "version", "expected_source_revision") {
			return store.GoExportSetRequest{}, false
		}
		request.Entries = append(request.Entries, member)
	}
	if request.Validate() != nil {
		return store.GoExportSetRequest{}, false
	}
	return request, true
}

func (s *Server) goExportSetManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) bool {
	if path != "go/export-sets/preview" {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if r.Method != "POST" {
		exportMethod(w, "POST")
		return true
	}
	if r.URL.RawQuery != "" {
		respondErr(w, store.ErrGoExportSetInput)
		return true
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, store.MaxGoExportSetRequest))
	if err != nil {
		respondErr(w, store.ErrGoExportSetInput)
		return true
	}
	request, valid := decodeGoExportSet(raw)
	if !valid {
		respondErr(w, store.ErrGoExportSetInput)
		return true
	}
	plan, err := s.DB.PlanGoExportSet(r.Context(), i, request)
	if err != nil {
		respondErr(w, err)
		return true
	}
	writeJSON(w, 200, map[string]any{"manifest": json.RawMessage(plan.Bytes()), "object": plan.Object(), "physical_objects_verified": false, "durable_session_created": false, "trust": "Unsigned metadata preview from one tenant-scoped repeatable-read transaction. No package object was opened or pinned, no session was created, and dependency closure, checksum authority and destination admission are unverified. Durable common-snapshot creation and physical verification remain required before collection."})
	return true
}
