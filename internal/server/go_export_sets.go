// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	if path != "go/export-sets" && !strings.HasPrefix(path, "go/export-sets/") {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	parts := strings.Split(path, "/")
	preview := len(parts) == 3 && parts[2] == "preview"
	if len(parts) == 2 || preview {
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
		key := r.Header.Get("Idempotency-Key")
		if !preview {
			if len(r.Header.Values("Idempotency-Key")) != 1 {
				respondErr(w, store.ErrGoExportSetInput)
				return true
			}
			res, replayed, err := s.DB.ReplayGoExportSet(r.Context(), i, request, key)
			if err != nil {
				respondErr(w, err)
				return true
			}
			if replayed {
				exportResult(w, res)
				return true
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		plan, err := s.DB.PlanGoExportSet(ctx, i, request)
		if err != nil {
			respondErr(w, err)
			return true
		}
		if preview {
			writeJSON(w, 200, map[string]any{"manifest": json.RawMessage(plan.Bytes()), "object": plan.Object(), "physical_objects_verified": false, "durable_session_created": false, "trust": "Unsigned metadata preview from one tenant-scoped repeatable-read transaction. No package object was opened or pinned, no session was created, and dependency closure, checksum authority and destination admission are unverified. Creation must physically inspect every member and revalidate current source identity under the tenant mutation fence."})
			return true
		}
		if s.ExportSessionLimit < 1 || s.ExportSessionLimit > 1000000 || s.Blobs == nil {
			respondErr(w, store.ErrGoExportLimit)
			return true
		}
		members, err := plan.Members()
		if err != nil {
			respondErr(w, err)
			return true
		}
		for _, member := range members {
			if err = s.verifyGoExportPlan(ctx, i, member); err != nil {
				respondErr(w, err)
				return true
			}
		}
		o := plan.Object()
		staged, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(plan.Bytes()), o.Digest, o.Size)
		if err != nil {
			respondErr(w, err)
			return true
		}
		result, err := s.DB.CommitGoExportSet(ctx, i, plan, staged, key, s.ExportSessionLimit)
		if err != nil {
			respondErr(w, err)
			return true
		}
		exportResult(w, result)
		return true
	}
	if len(parts) < 3 || !store.ValidGoExportID(parts[2]) {
		respondErr(w, store.ErrGoExportSetInput)
		return true
	}
	id := parts[2]
	if len(parts) == 3 {
		if r.Method != "GET" {
			exportMethod(w, "GET")
			return true
		}
		if r.URL.RawQuery != "" {
			respondErr(w, store.ErrGoExportSetInput)
			return true
		}
		v, err := s.DB.GoExportSet(r.Context(), i, id)
		if err != nil {
			respondErr(w, err)
			return true
		}
		writeJSON(w, 200, v)
		return true
	}
	if len(parts) == 4 && parts[3] == "control" {
		if r.Method != "POST" {
			exportMethod(w, "POST")
			return true
		}
		if r.URL.RawQuery != "" || len(r.Header.Values("Idempotency-Key")) != 1 {
			respondErr(w, store.ErrGoExportSetInput)
			return true
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var request store.GoExportChange
		if err != nil || !decodeGoExport(raw, &request, "action", "expected_generation", "lifetime_seconds", "manifest_sha256") || request.Validate() != nil {
			respondErr(w, store.ErrGoExportSetInput)
			return true
		}
		v, err := s.DB.ChangeGoExportSet(r.Context(), i, id, request, r.Header.Get("Idempotency-Key"))
		if err != nil {
			respondErr(w, err)
			return true
		}
		exportResult(w, v)
		return true
	}
	root, kind := 0, ""
	if len(parts) == 4 && parts[3] == "manifest" {
		kind = "manifest"
	} else if len(parts) == 6 && parts[3] == "roots" {
		n, err := strconv.ParseInt(parts[4], 10, 32)
		if err != nil || n < 0 || n >= store.MaxGoExportSetEntries || strconv.FormatInt(n, 10) != parts[4] {
			respondErr(w, store.ErrGoExportSetInput)
			return true
		}
		root = int(n)
		kind = parts[5]
		if kind != "zip" && kind != "mod" && kind != "info" {
			respondErr(w, store.ErrGoExportSetInput)
			return true
		}
	}
	if kind != "manifest" && kind != "zip" && kind != "mod" && kind != "info" {
		respondErr(w, store.ErrGoExportSetInput)
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		exportMethod(w, "GET, HEAD")
		return true
	}
	q, valid := journalQuery(r.URL.RawQuery, "generation")
	generation, ok := journalInteger(q, "generation", 0)
	if !valid || !ok || generation < 1 {
		respondErr(w, store.ErrGoExportSetInput)
		return true
	}
	s.serveGoExportSet(w, r, i, id, generation, root, kind)
	return true
}

func (s *Server) serveGoExportSet(w http.ResponseWriter, r *http.Request, i store.Identity, id string, generation int64, root int, kind string) {
	v, err := s.DB.GoExportSetObject(r.Context(), i, id, generation, root, kind)
	if err != nil {
		respondErr(w, err)
		return
	}
	duration := min(v.Session.ExpiresAt.Sub(v.Session.ServerTime), 90*time.Second)
	if duration <= 0 {
		respondErr(w, store.ErrGoExportExpired)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), duration)
	defer cancel()
	f, err := s.Blobs.OpenVerified(ctx, i.Tenant, v.Object.Digest, v.Object.Size)
	if err != nil {
		respondErr(w, err)
		return
	}
	defer f.Close()
	check := func(ctx context.Context) error {
		current, err := s.DB.GoExportSetObject(ctx, i, id, generation, root, kind)
		if err != nil {
			return err
		}
		if current.Object != v.Object {
			return store.ErrGoExportSetChanged
		}
		return nil
	}
	if err = check(ctx); err != nil {
		respondErr(w, err)
		return
	}
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetWriteDeadline(deadline)
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	work, finish, stop := keepLease(ctx, 3*time.Second, check, func() { _ = f.Close(); _ = controller.SetWriteDeadline(time.Now()) })
	defer stop()
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("ETag", `"sha256:`+v.Object.Digest+`"`)
	w.Header().Set("X-Checksum-Sha256", v.Object.Digest)
	w.Header().Set("X-Cratectl-Export-Generation", strconv.FormatInt(generation, 10))
	media := "application/json"
	if kind == "zip" {
		media = "application/zip"
	}
	if kind == "mod" {
		media = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", media)
	http.ServeContent(w, r.WithContext(work), "go-export-set."+kind, v.Session.CreatedAt, exportReadSeeker{work, f})
	_ = finish()
}
