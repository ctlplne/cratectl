// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

const maxGoRequirementRequest = 2 << 20
const maxGoRequirementResponse = 16 << 20

type goRequirementRequest struct {
	Repository             string `json:"repository"`
	ExpectedSourceRevision int64  `json:"expected_source_revision"`
	MainGoMod              string `json:"main_go_mod"`
	LifetimeSeconds        int    `json:"lifetime_seconds"`
	MaxArtifactBytes       int64  `json:"max_artifact_bytes"`
}

func decodeGoRequirementRequest(raw []byte) (goRequirementRequest, bool) {
	var r goRequirementRequest
	if !decodeBoundedGoExport(raw, maxGoRequirementRequest, &r, "repository", "expected_source_revision", "main_go_mod", "lifetime_seconds", "max_artifact_bytes") ||
		!store.Name.MatchString(r.Repository) || r.ExpectedSourceRevision < 0 || len(r.MainGoMod) < 1 || len(r.MainGoMod) > gomodule.MaxGoMod ||
		r.LifetimeSeconds < 60 || r.LifetimeSeconds > 3600 || r.MaxArtifactBytes < 1 || r.MaxArtifactBytes > store.MaxGoExportSetArtifactBytes {
		return goRequirementRequest{}, false
	}
	return r, true
}

func (s *Server) goRequirementPreview(w http.ResponseWriter, r *http.Request, i store.Identity) {
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Method != "POST" {
		exportMethod(w, "POST")
		return
	}
	if r.URL.RawQuery != "" {
		fail(w, 400, "invalid_go_requirement_request", "Remove query parameters and supply the documented project fields in the JSON body.")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxGoRequirementRequest))
	input, valid := decodeGoRequirementRequest(raw)
	if err != nil || !valid {
		fail(w, 400, "invalid_go_requirement_request", "Supply a hosted repository, its exact source revision, main_go_mod as a JSON string, a lifetime from 60 through 3600 seconds and a positive artifact byte budget through 64 GiB.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	type loadedInput struct {
		plan store.GoExportPlan
		raw  []byte
	}
	loaded := map[gomodule.Coordinate]loadedInput{}
	reads := []store.GoExportPlan{}
	graph, err := gomodule.ResolveRequirements(ctx, []byte(input.MainGoMod), func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
		if prior, ok := loaded[c]; ok {
			if int64(len(prior.raw)) > maximum {
				return nil, gomodule.ErrGraphLimit
			}
			return bytes.Clone(prior.raw), nil
		}
		p, err := s.DB.PlanGoExport(ctx, i, store.GoExportRequest{Repository: input.Repository, Module: c.Module,
			Version: c.Version, ExpectedSourceRevision: input.ExpectedSourceRevision, LifetimeSeconds: input.LifetimeSeconds})
		if err != nil {
			return nil, err
		}
		object := p.Objects()[1] // Original .mod in the common ZIP/mod/info order.
		if object.Size < 1 || object.Size > maximum {
			return nil, gomodule.ErrGraphLimit
		}
		if s.Blobs == nil {
			return nil, store.ErrGoExportSetChanged
		}
		file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(file, object.Size+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || int64(len(body)) != object.Size || crypt.Digest(body) != object.Digest {
			return nil, store.ErrGoExportSetChanged
		}
		loaded[c] = loadedInput{p, bytes.Clone(body)}
		reads = append(reads, p)
		return body, nil
	}, gomodule.DefaultGraphLimits())
	if err != nil {
		switch {
		case errors.Is(err, gomodule.ErrGraphLimit):
			fail(w, 413, "go_requirement_budget", "Reduce the project graph or metadata size and prepare a new preview.")
		case errors.Is(err, gomodule.ErrGraphUnsupported), errors.Is(err, gomodule.ErrModule):
			fail(w, 400, "invalid_go_requirement_input", "Supply a canonical single-project go.mod with versioned dependencies. Local replacements and excluded direct roots need explicit immutable resolution.")
		default:
			respondErr(w, err)
		}
		return
	}
	if len(graph.BuildList) == 0 {
		fail(w, 400, "empty_go_requirement_selection", "This project selects no external module versions. Supply the intended project requirements before preparing an export.")
		return
	}
	selection := store.GoExportSetRequest{LifetimeSeconds: input.LifetimeSeconds, MaxArtifactBytes: input.MaxArtifactBytes}
	for _, selected := range graph.BuildList {
		selection.Entries = append(selection.Entries, store.GoExportSetEntry{Repository: input.Repository, Module: selected.Source.Module,
			Version: selected.Source.Version, ExpectedSourceRevision: input.ExpectedSourceRevision})
	}
	plan, err := s.DB.PlanGoExportSetAfterReads(ctx, i, selection, reads)
	if err != nil {
		respondErr(w, err)
		return
	}
	inputs := make([]map[string]any, 0, len(graph.Inputs))
	for _, examined := range graph.Inputs {
		inputs = append(inputs, map[string]any{"logical_module": examined.Logical.Module, "logical_version": examined.Logical.Version,
			"source_module": examined.Source.Module, "source_version": examined.Source.Version, "go_version": examined.GoVersion,
			"mod_sha256": examined.GoModSHA256, "mod_bytes": examined.Bytes})
	}
	response, err := json.Marshal(map[string]any{"profile": "cratectl.go.requirement-preview.v1", "selection": selection,
		"main_go_mod_sha256": graph.MainGoModSHA256, "main_go_version": graph.GoVersion, "minimum_go_version": graph.MinimumGoVersion,
		"suggested_toolchain": graph.SuggestedToolchain, "graph_pruned": graph.Pruned, "examined_inputs": inputs,
		"requirements": graph.Requirements, "metadata_bytes": graph.MetadataBytes, "manifest": json.RawMessage(plan.Bytes()),
		"metadata_inputs_revalidated": true, "durable_session_created": false, "physical_payloads_verified": false,
		"dependency_closure": false, "checksum_authority_verified": false, "current_registry_admission": false,
		"trust": "Inspect selected versions and current hosted-source eligibility. Every examined input and selected root shares the final observation. Complete package/platform closure, immutable graph proof and current destination admission remain unverified. Creation requires fresh guarded source checks."})
	if err != nil || len(response)+1 > maxGoRequirementResponse {
		fail(w, 413, "go_requirement_response_budget", "Choose a smaller graph and prepare a new complete preview.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(append(response, '\n'))
}
