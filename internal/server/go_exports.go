// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

func decodeGoExport(raw []byte, out any, required ...string) bool {
	return decodeBoundedGoExport(raw, 4096, out, required...)
}

func decodeBoundedGoExport(raw []byte, limit int, out any, required ...string) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		allowed := false
		for _, key := range required {
			allowed = allowed || name == key
		}
		if !allowed {
			return false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
		seen[name] = true
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	if len(seen) != len(required) {
		return false
	}
	if _, err = d.Token(); err != io.EOF {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

func exportMethod(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	fail(w, 405, "method_not_allowed", "Use the documented export method; downloads and snapshot state changes are separate operations.")
}

func exportResult(w http.ResponseWriter, res store.Result) {
	if res.Replay {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
}

func (s *Server) goExportManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) bool {
	p := strings.Split(path, "/")
	if len(p) < 2 || len(p) > 4 || p[0] != "go" || p[1] != "exports" {
		return false
	}
	preview := len(p) == 3 && p[2] == "preview"
	if len(p) == 4 && p[3] != "manifest" && p[3] != "zip" && p[3] != "mod" && p[3] != "info" {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if len(p) >= 3 && !preview && !store.ValidGoExportID(p[2]) {
		respondErr(w, store.ErrGoExportInput)
		return true
	}
	if (len(p) == 2 && r.Method == "POST") || preview {
		if r.Method != "POST" {
			exportMethod(w, "POST")
			return true
		}
		if r.URL.RawQuery != "" {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var req store.GoExportRequest
		if err != nil || !decodeGoExport(raw, &req, "repository", "module", "version", "expected_source_revision", "lifetime_seconds") || req.Validate() != nil {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		key := r.Header.Get("Idempotency-Key")
		if !preview && len(r.Header.Values("Idempotency-Key")) != 1 {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		if !preview {
			res, replay, err := s.DB.ReplayGoExport(r.Context(), i, req, key)
			if err != nil {
				respondErr(w, err)
				return true
			}
			if replay {
				exportResult(w, res)
				return true
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		plan, err := s.DB.PlanGoExport(ctx, i, req)
		if err != nil {
			respondErr(w, err)
			return true
		}
		if preview {
			writeJSON(w, 200, map[string]any{"manifest": json.RawMessage(plan.Bytes()), "object": plan.Object(), "physical_objects_verified": false, "trust": "Unsigned preview. Creation revalidates current byte/policy identity after staging; authenticate its original creation event through a complete externally signed journal before offline attribution."})
			return true
		}
		if s.ExportSessionLimit < 1 || s.ExportSessionLimit > 1000000 || s.Blobs == nil {
			respondErr(w, store.ErrGoExportLimit)
			return true
		}
		if err := s.verifyGoExportPlan(ctx, i, plan); err != nil {
			respondErr(w, err)
			return true
		}
		manifest := plan.Bytes()
		object := plan.Object()
		staged, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(manifest), object.Digest, object.Size)
		if err != nil {
			respondErr(w, err)
			return true
		}
		res, err := s.DB.CommitGoExport(ctx, i, plan, staged, key, s.ExportSessionLimit)
		if err != nil {
			respondErr(w, err)
			return true
		}
		exportResult(w, res)
		return true
	}
	if len(p) == 2 {
		if r.Method != "GET" {
			exportMethod(w, "GET, POST")
			return true
		}
		q, valid := journalQuery(r.URL.RawQuery, "after", "limit")
		after, a := journalInteger(q, "after", 0)
		limit, l := journalInteger(q, "limit", 25)
		if !valid || !a || !l || limit < 1 || limit > 100 {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		items, more, err := s.DB.GoExports(r.Context(), i, after, int(limit))
		if err != nil {
			respondErr(w, err)
			return true
		}
		next := int64(0)
		if more {
			next = items[len(items)-1].CreatedSequence
		}
		writeJSON(w, 200, map[string]any{"items": items, "more": more, "next_after": next})
		return true
	}
	if len(p) == 3 {
		if r.URL.RawQuery != "" {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		if r.Method == "GET" {
			v, err := s.DB.GoExport(r.Context(), i, p[2])
			if err != nil {
				respondErr(w, err)
			} else {
				writeJSON(w, 200, v)
			}
			return true
		}
		if r.Method != "PATCH" {
			exportMethod(w, "GET, PATCH")
			return true
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var req store.GoExportChange
		if err != nil || !decodeGoExport(raw, &req, "action", "expected_generation", "lifetime_seconds", "manifest_sha256") || req.Validate() != nil {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			respondErr(w, store.ErrGoExportInput)
			return true
		}
		res, err := s.DB.ChangeGoExport(r.Context(), i, p[2], req, r.Header.Get("Idempotency-Key"))
		if err != nil {
			respondErr(w, err)
		} else {
			exportResult(w, res)
		}
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		exportMethod(w, "GET, HEAD")
		return true
	}
	q, valid := journalQuery(r.URL.RawQuery, "generation")
	gen, g := journalInteger(q, "generation", 0)
	if !valid || !g || gen < 1 || len(q["generation"]) != 1 || len(r.Header.Values("Range")) > 1 || len(r.Header.Get("Range")) > 1024 || strings.Contains(r.Header.Get("Range"), ",") {
		respondErr(w, store.ErrGoExportInput)
		return true
	}
	s.serveGoExport(w, r, i, p[2], gen, p[3])
	return true
}

func (s *Server) verifyGoExportPlan(ctx context.Context, i store.Identity, p store.GoExportPlan) error {
	objects := p.Objects()
	var files [3]*os.File
	defer func() {
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	for n, o := range objects {
		var err error
		files[n], err = s.Blobs.OpenVerified(ctx, i.Tenant, o.Digest, o.Size)
		if err != nil {
			return err
		}
	}
	mod, err := io.ReadAll(io.LimitReader(files[1], gomodule.MaxGoMod+1))
	if err != nil {
		return err
	}
	info, err := io.ReadAll(io.LimitReader(files[2], gomodule.MaxVersionInfo+1))
	if err != nil {
		return err
	}
	_, err = gomodule.InspectRepresentations(ctx, files[0], objects[0].Size, p.Coordinate(), mod, info, ziparchive.Limits{CompressedBytes: 512 << 20, ExpandedBytes: 512 << 20, DirectoryBytes: 16 << 20, Files: 16384})
	if err != nil {
		return store.ErrGoModuleUnvalidated
	}
	return nil
}

type exportReadSeeker struct {
	ctx context.Context
	f   *os.File
}

func (v exportReadSeeker) Read(p []byte) (int, error) {
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	return v.f.Read(p)
}
func (v exportReadSeeker) Seek(off int64, whence int) (int64, error) {
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	return v.f.Seek(off, whence)
}

func (s *Server) serveGoExport(w http.ResponseWriter, r *http.Request, i store.Identity, id string, generation int64, kind string) {
	v, err := s.DB.GoExportObject(r.Context(), i, id, generation, kind)
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
	current, err := s.DB.GoExportObject(ctx, i, id, generation, kind)
	if err != nil {
		respondErr(w, err)
		return
	}
	if current.Object != v.Object {
		respondErr(w, store.ErrGoExportChanged)
		return
	}
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetWriteDeadline(deadline)
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	work, finish, stop := keepLease(ctx, 3*time.Second, func(check context.Context) error {
		current, err := s.DB.GoExportObject(check, i, id, generation, kind)
		if err != nil {
			return err
		}
		if current.Object != v.Object {
			return store.ErrGoExportChanged
		}
		return nil
	}, func() { _ = f.Close(); _ = controller.SetWriteDeadline(time.Now()) })
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
	http.ServeContent(w, r.WithContext(work), "go-export."+kind, v.Session.CreatedAt, exportReadSeeker{work, f})
	_ = finish() // HTTP bytes already sent are never a delivery acknowledgment.
}
