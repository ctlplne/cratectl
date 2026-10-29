// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) deleteOCI(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, image, kind, ref string) {
	_, e := s.DB.DeleteOCI(r.Context(), i, repo.Name, image, kind, ref, s.NativeVersionLimit)
	if e != nil {
		respondErr(w, e)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) lifecycleManagement(w http.ResponseWriter, r *http.Request, i store.Identity, p string) bool {
	bits := strings.Split(p, "/")
	repository := len(bits) == 3 && bits[0] == "repositories" && bits[2] == "state"
	artifact := len(bits) == 4 && bits[0] == "repositories" && bits[2] == "artifacts" && bits[3] == "lifecycle"
	if !repository && !artifact {
		return false
	}
	if !store.Name.MatchString(bits[1]) {
		fail(w, 400, "invalid_repository", "Choose one repository name.")
		return true
	}
	if repository && i.Role != "admin" || artifact && !i.CanWrite() {
		respondErr(w, store.ErrDenied)
		return true
	}
	repo := bits[1]
	if r.Method == "GET" {
		if repository {
			if r.URL.RawQuery != "" {
				fail(w, 400, "invalid_query", "Read repository state without query parameters.")
				return true
			}
			state, e := s.DB.RepositoryState(r.Context(), i, repo)
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, state)
			}
		} else {
			path := r.URL.Query().Get("path")
			if len(r.URL.Query()) != 1 || len(r.URL.Query()["path"]) != 1 || len(path) > 2048 {
				fail(w, 400, "invalid_path", "Supply one canonical OCI digest path in the path query.")
				return true
			}
			state, e := s.DB.ArtifactState(r.Context(), i, repo, path)
			if e != nil {
				respondErr(w, e)
			} else {
				writeJSON(w, 200, state)
			}
		}
		return true
	}
	if r.Method != "PUT" {
		w.Header().Set("Allow", "GET, PUT")
		fail(w, 405, "method_not_allowed", "Read state with GET; preview or apply with PUT.")
		return true
	}
	if r.URL.RawQuery != "" {
		fail(w, 400, "invalid_query", "Send lifecycle parameters in the JSON body.")
		return true
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if e != nil {
		fail(w, 413, "request_limit", "Limit lifecycle JSON to 16 KiB.")
		return true
	}
	var repoInput store.RepositoryStateRequest
	var artifactInput store.ArtifactStateRequest
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields["expected_revision"] == nil || string(fields["expected_revision"]) == "null" {
		fail(w, 400, "revision_required", "Read current state and supply its expected_revision explicitly.")
		return true
	}
	valid := false
	dry := false
	if repository {
		valid = decodeManagement(data, &repoInput)
		dry = repoInput.DryRun
	} else {
		valid = decodeManagement(data, &artifactInput)
		dry = artifactInput.DryRun
	}
	if !valid {
		fail(w, 400, "invalid_lifecycle_request", "Use a documented action, exact digest/revision and a bounded reason without controls.")
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !dry && (len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00")) {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key; reuse it only for the identical request.")
		return true
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	var result store.Result
	if !dry {
		var prior store.Result
		var found bool
		if artifact {
			prior, found, e = s.DB.ReplayArtifactLifecycle(r.Context(), i, repo, key, fp, artifactInput)
		} else {
			prior, found, e = s.DB.ReplayMutation(r.Context(), i, key, fp)
		}
		if e != nil {
			respondErr(w, e)
			return true
		}
		if found {
			writeLifecycleResult(w, prior)
			return true
		}
	}
	if repository {
		result, e = s.DB.ChangeRepositoryState(r.Context(), i, repo, key, fp, repoInput, s.NativeVersionLimit)
	} else {
		var verified []store.Artifact
		if artifactInput.Action == "restore" && !dry {
			verified, e = s.DB.RestorationGraph(r.Context(), i, repo, artifactInput)
			if e == nil {
				e = s.verifyRestoration(r, i, verified)
			}
		}
		if e == nil {
			result, e = s.DB.ChangeArtifactState(r.Context(), i, repo, key, fp, artifactInput, s.NativeVersionLimit, verified)
		}
	}
	if e != nil {
		respondErr(w, e)
	} else {
		writeLifecycleResult(w, result)
	}
	return true
}
func writeLifecycleResult(w http.ResponseWriter, result store.Result) {
	if result.Replay {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}
func (s *Server) verifyRestoration(r *http.Request, i store.Identity, objects []store.Artifact) error {
	if s.Blobs == nil {
		return blob.ErrIntegrity
	}
	for _, a := range objects {
		f, e := s.Blobs.OpenVerified(r.Context(), i.Tenant, a.Digest, a.Size)
		if e != nil {
			return blob.ErrIntegrity
		}
		if strings.HasSuffix(a.Path, "/manifests/sha256:"+a.Digest) {
			data, e := io.ReadAll(io.LimitReader(f, ociManifestBytes+1))
			_ = f.Close()
			if e != nil || len(data) > ociManifestBytes {
				return blob.ErrIntegrity
			}
			parsed, e := parseOCIManifest(data, a.MediaType)
			if e != nil {
				return blob.ErrIntegrity
			}
			var retained store.OCIManifestMetadata
			image := a.Path[:strings.LastIndex(a.Path, "/manifests/")]
			if json.Unmarshal(a.Metadata, &retained) != nil || !reflect.DeepEqual(parsed.metadata(image), retained) {
				return blob.ErrIntegrity
			}
		} else {
			_ = f.Close()
		}
	}
	return nil
}
