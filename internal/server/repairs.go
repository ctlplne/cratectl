// SPDX-License-Identifier: BUSL-1.1
package server

import (
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func (s *Server) repairManagement(w http.ResponseWriter, r *http.Request, i store.Identity, path string) bool {
	bits := strings.Split(path, "/")
	plan := len(bits) == 4 && bits[0] == "repositories" && bits[2] == "artifacts" && bits[3] == "repairs"
	source := len(bits) == 4 && bits[0] == "maintenance" && bits[1] == "repairs" && bits[3] == "source"
	if !plan && !source {
		return false
	}
	if i.Role != "admin" {
		respondErr(w, store.ErrDenied)
		return true
	}
	if r.URL.RawQuery != "" {
		fail(w, 400, "invalid_repair", "Send repair parameters in the JSON plan and bytes in its source request.")
		return true
	}
	if plan && r.Method != "POST" || source && r.Method != "PUT" {
		fail(w, 405, "method_not_allowed", "POST a repair plan, then PUT its exact source bytes; inspect progress through the jobs API.")
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if plan {
		if !store.Name.MatchString(bits[1]) {
			respondErr(w, store.ErrRepairInput)
			return true
		}
		data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		if e != nil {
			fail(w, 413, "request_limit", "Limit the repair plan to 8 KiB.")
			return true
		}
		input, valid := decodeRepairRequest(data)
		if !valid {
			respondErr(w, store.ErrRepairInput)
			return true
		}
		if !input.DryRun && !repairKey(key) {
			fail(w, 400, "idempotency_key_required", "Use an 8–128 character Idempotency-Key for the identical repair plan.")
			return true
		}
		fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
		if !input.DryRun {
			if result, found, e := s.DB.ReplayMutation(r.Context(), i, key, fp); e != nil {
				respondErr(w, e)
				return true
			} else if found {
				writeLifecycleResult(w, result)
				return true
			}
		}
		if _, e = s.DB.PreviewRepair(r.Context(), i, bits[1], input, s.SweepTargetBudget); e != nil {
			respondErr(w, e)
			return true
		}
		root, e := s.Blobs.InventoryRoot(i.Tenant)
		if e != nil {
			respondErr(w, e)
			return true
		}
		result, e := s.DB.StartRepair(r.Context(), i, bits[1], key, fp, root, input, s.SweepTargetBudget)
		if e != nil {
			respondErr(w, e)
		} else {
			writeLifecycleResult(w, result)
		}
		return true
	}
	if !repairKey(key) {
		fail(w, 400, "idempotency_key_required", "Use an 8–128 character Idempotency-Key when submitting this repair's exact source bytes.")
		return true
	}
	// The plan fixes digest and size, so a source replay confirms that accepted
	// upload without reading another potentially enormous body.
	fp := crypt.Digest([]byte(r.Method + "\n" + r.URL.Path + "\nexact-planned-repair-source"))
	if result, found, e := s.DB.ReplayMutation(r.Context(), i, key, fp); e != nil {
		respondErr(w, e)
		return true
	} else if found {
		writeLifecycleResult(w, result)
		return true
	}
	target, e := s.DB.RepairForSource(r.Context(), i, bits[2])
	if e != nil {
		respondErr(w, e)
		return true
	}
	if target.SourceReady {
		respondErr(w, store.ErrRepairChanged)
		return true
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		fail(w, 415, "repair_source_type", "Send application/octet-stream with the exact retained artifact bytes.")
		return true
	}
	if r.ContentLength >= 0 && r.ContentLength != target.Target.Size {
		respondErr(w, store.ErrRepairInput)
		return true
	}
	select {
	case s.fillSlots <- struct{}{}:
		defer func() { <-s.fillSlots }()
	default:
		fail(w, 503, "repair_upload_saturated", "Retry after another bounded fill or repair source upload finishes.")
		return true
	}
	receipt, e := s.Blobs.StageRepair(r.Context(), i.Tenant, target.Root, target.Target.Digest, target.Target.Size, r.Body)
	if e != nil {
		respondErr(w, e)
		return true
	}
	result, e := s.DB.AcceptRepairSource(r.Context(), i, bits[2], key, fp, receipt)
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, result)
	}
	return true
}
func repairKey(key string) bool {
	return len(key) >= 8 && len(key) <= 128 && !strings.ContainsAny(key, "\r\n\x00")
}

func decodeRepairRequest(data []byte) (store.RepairRequest, bool) {
	var input store.RepairRequest
	var fields map[string]json.RawMessage
	if len(data) > 8192 || uniqueOCIJSON(data) != nil || !decodeManagement(data, &input) || json.Unmarshal(data, &fields) != nil || fields["expected_source_revision"] == nil || string(fields["expected_source_revision"]) == "null" || input.Validate() != nil {
		return input, false
	}
	for key := range fields {
		switch key {
		case "path", "digest", "expected_source_revision", "reason", "provenance", "dry_run":
		default:
			return input, false
		}
	}
	return input, true
}
