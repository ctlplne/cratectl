// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) goRequirementManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) {
	w.Header().Set("Cache-Control", "private, no-store")
	parts := strings.Split(path, "/")
	if len(parts) == 3 {
		if r.Method != "POST" {
			exportMethod(w, "POST")
			return
		}
		if r.URL.RawQuery != "" || len(r.Header.Values("Idempotency-Key")) != 1 {
			respondGoRequirementErr(w, store.ErrGoRequirementExport)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxGoRequirementRequest))
		request, valid := decodeGoRequirementRequest(raw)
		if err != nil || !valid {
			respondGoRequirementErr(w, store.ErrGoRequirementExport)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		key := r.Header.Get("Idempotency-Key")
		res, replay, err := s.DB.ReplayGoRequirementExport(ctx, i, request, key)
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		if replay {
			exportResult(w, res)
			return
		}
		if s.ExportSessionLimit < 1 || s.ExportSessionLimit > 1000000 || s.Blobs == nil {
			respondErr(w, store.ErrGoExportLimit)
			return
		}
		graph, reads, err := s.loadGoRequirements(ctx, i, request)
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		if len(graph.BuildList) == 0 {
			fail(w, 400, "empty_go_requirement_selection", "This project selects no external module versions. Supply the intended project requirements before creating an export.")
			return
		}
		plan, err := s.DB.PlanGoRequirementExport(ctx, i, request, reads)
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		members, err := plan.Members()
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		for _, member := range members {
			if err := s.verifyGoExportPlan(ctx, i, member); err != nil {
				respondGoRequirementErr(w, err)
				return
			}
		}
		metadata, err := plan.Metadata()
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		staged := make([]blob.Object, 0, len(metadata))
		for _, item := range metadata {
			o, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(item.Bytes), item.Object.Digest, item.Object.Size)
			if err != nil {
				respondGoRequirementErr(w, err)
				return
			}
			staged = append(staged, o)
		}
		res, err = s.DB.CommitGoRequirementExport(ctx, i, plan, staged, key, s.ExportSessionLimit)
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		exportResult(w, res)
		return
	}
	if len(parts) < 4 || !store.ValidGoExportID(parts[3]) {
		respondGoRequirementErr(w, store.ErrGoRequirementExport)
		return
	}
	id := parts[3]
	if len(parts) == 4 {
		if r.Method != "GET" {
			exportMethod(w, "GET")
			return
		}
		if r.URL.RawQuery != "" {
			respondGoRequirementErr(w, store.ErrGoRequirementExport)
			return
		}
		v, err := s.DB.GoRequirementExport(r.Context(), i, id)
		if err != nil {
			respondGoRequirementErr(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	source, kind := 0, ""
	if len(parts) == 5 {
		kind = parts[4]
		if kind != "manifest" && kind != "main" && kind != "proof" && kind != "selection" {
			respondGoRequirementErr(w, store.ErrGoRequirementExport)
			return
		}
	} else if len(parts) == 7 && parts[4] == "inputs" {
		n, err := strconv.ParseInt(parts[5], 10, 32)
		if err != nil || n < 0 || n >= gomodule.MaxRequirementProofSources || strconv.FormatInt(n, 10) != parts[5] || (parts[6] != "manifest" && parts[6] != "mod") {
			respondGoRequirementErr(w, store.ErrGoRequirementExport)
			return
		}
		source = int(n)
		kind = "source-" + parts[6]
	} else {
		respondGoRequirementErr(w, store.ErrGoRequirementExport)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		exportMethod(w, "GET, HEAD")
		return
	}
	q, valid := journalQuery(r.URL.RawQuery, "generation")
	generation, ok := journalInteger(q, "generation", 0)
	if !valid || !ok || generation < 1 {
		respondGoRequirementErr(w, store.ErrGoRequirementExport)
		return
	}
	s.serveGoRequirementExport(w, r, i, id, generation, source, kind)
}

func (s *Server) serveGoRequirementExport(w http.ResponseWriter, r *http.Request, i store.Identity, id string, generation int64, source int, kind string) {
	v, err := s.DB.GoRequirementExportObject(r.Context(), i, id, generation, source, kind)
	if err != nil {
		respondGoRequirementErr(w, err)
		return
	}
	duration := min(v.Session.ExpiresAt.Sub(v.Session.ServerTime), 90*time.Second)
	if duration <= 0 || s.Blobs == nil {
		respondErr(w, store.ErrGoExportExpired)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), duration)
	defer cancel()
	f, err := s.Blobs.OpenVerified(ctx, i.Tenant, v.Object.Digest, v.Object.Size)
	if err != nil {
		respondGoRequirementErr(w, err)
		return
	}
	defer f.Close()
	check := func(ctx context.Context) error {
		current, err := s.DB.GoRequirementExportObject(ctx, i, id, generation, source, kind)
		if err != nil {
			return err
		}
		if current.Object != v.Object || current.Session.Manifest != v.Session.Manifest {
			return store.ErrGoExportSetChanged
		}
		return nil
	}
	if err = check(ctx); err != nil {
		respondGoRequirementErr(w, err)
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
	if kind == "main" || kind == "source-mod" {
		media = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", media)
	http.ServeContent(w, r.WithContext(work), "go-requirement-export."+kind, v.Session.CreatedAt, exportReadSeeker{work, f})
	_ = finish()
}
