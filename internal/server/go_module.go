// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func latestGoVersion(versions []string) string {
	for index := len(versions) - 1; index >= 0; index-- {
		v := versions[index]
		if semver.Prerelease(v) == "" && !module.IsPseudoVersion(v) {
			return v
		}
	}
	for index := len(versions) - 1; index >= 0; index-- {
		if !module.IsPseudoVersion(versions[index]) {
			return versions[index]
		}
	}
	latest := ""
	var instant time.Time
	for _, v := range versions {
		t, e := module.PseudoVersionTime(v)
		if e == nil && (latest == "" || t.After(instant)) {
			latest, instant = v, t
		}
	}
	if latest != "" {
		return latest
	}
	return ""
}

func latestGoSelection(view store.GoModuleVersionView) (string, error) {
	if version := latestGoVersion(view.Versions); version != "" {
		return version, nil
	}
	if view.Known {
		return "", store.ErrDenied
	}
	return "", store.ErrNotFound
}

func (s *Server) goModule(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || r.URL.RawQuery != "" {
		fail(w, 400, "invalid_go_module", "Use canonical escaped Go module paths, versions and native info/mod/zip/list/latest operations without query parameters.")
		return
	}
	if repo.Mode != "hosted" && repo.Mode != "group" {
		fail(w, 405, "go_mode_unimplemented", "This Go adapter admits hosted repositories and groups over hosted sources. Proxy retrieval remains unimplemented.")
		return
	}
	if r.Method == "PUT" && request.Operation == "zip" {
		s.publishGoModule(w, r, i, repo, request.Coordinate)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Read native metadata/content with GET or HEAD; publish one complete module ZIP with PUT and its stable X-Cratectl-Module-Time.")
		return
	}
	if request.Operation == "list" || request.Operation == "latest" {
		view, admissions, e := s.prepareGoModuleView(r.Context(), i, repo, request.Module, false)
		if e != nil {
			respondErr(w, e)
			return
		}
		if request.Operation == "latest" {
			version, e := latestGoSelection(view)
			if e != nil {
				respondErr(w, e)
				return
			}
			c := gomodule.Coordinate{Module: request.Module, Version: version}
			s.serveArtifact(w, r, i, repo.Name, c.Prefix()+".info")
			return
		}
		versions := view.Versions
		var b strings.Builder
		for _, v := range versions {
			if !module.IsPseudoVersion(v) {
				b.WriteString(v)
				b.WriteByte('\n')
			}
		}
		if int64(b.Len()) > s.NativeMetadataBytes {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
		current, e := s.DB.GoModuleView(r.Context(), i, repo.Name, request.Module, s.NativeVersionLimit, s.NativeMetadataBytes, admissions...)
		if e != nil {
			respondErr(w, e)
			return
		}
		if current.Known != view.Known || !slices.Equal(current.Versions, versions) {
			respondErr(w, store.ErrConflict)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
		if r.Method == "GET" {
			io.WriteString(w, b.String())
		}
		return
	}
	s.serveArtifact(w, r, i, repo.Name, p)
}

func (s *Server) publishGoModule(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, c gomodule.Coordinate) {
	values := r.Header.Values("X-Cratectl-Module-Time")
	if len(values) != 1 {
		fail(w, 400, "invalid_go_module_time", "Supply one stable RFC3339 publication timestamp in X-Cratectl-Module-Time; reuse it for identical retries.")
		return
	}
	info, e := gomodule.VersionInfo(c, values[0])
	if e != nil {
		fail(w, 400, "invalid_go_module_time", "Use one nonzero RFC3339 publication timestamp.")
		return
	}
	if r.ContentLength > s.GoModuleUploadBytes {
		fail(w, 413, "go_module_budget", "Reduce the module ZIP or adjust the configured resource budget.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.GoModuleUploadBytes)
	zipObject, e := s.Blobs.Put(r.Context(), i.Tenant, r.Body, r.Header.Get("X-Checksum-Sha256"), r.ContentLength)
	if e != nil {
		var limit *http.MaxBytesError
		if errors.As(e, &limit) {
			fail(w, 413, "go_module_budget", "Reduce the module ZIP or adjust the configured resource budget.")
		} else {
			respondErr(w, e)
		}
		return
	}
	f, e := s.Blobs.OpenVerified(r.Context(), i.Tenant, zipObject.Digest, zipObject.Size)
	if e != nil {
		respondErr(w, e)
		return
	}
	inspected, e := gomodule.InspectArchive(r.Context(), f, zipObject.Size, c, ziparchive.Limits{CompressedBytes: s.GoModuleUploadBytes, ExpandedBytes: s.GoModuleExpandedBytes, DirectoryBytes: s.GoModuleDirectoryBytes, Files: s.GoModuleFileLimit})
	f.Close()
	if e != nil {
		if r.Context().Err() != nil {
			respondErr(w, e)
		} else {
			fail(w, 400, "invalid_go_module_archive", "Use a bounded portable module@version ZIP with matching root go.mod; links, ambiguous names, ZIP64/split archives and incomplete metadata are unsupported.")
		}
		return
	}
	modObject, e := s.Blobs.Put(r.Context(), i.Tenant, bytes.NewReader(inspected.GoMod), "", int64(len(inspected.GoMod)))
	if e != nil {
		respondErr(w, e)
		return
	}
	infoObject, e := s.Blobs.Put(r.Context(), i.Tenant, bytes.NewReader(info), "", int64(len(info)))
	if e != nil {
		respondErr(w, e)
		return
	}
	metadata := store.GoModuleMetadata{Profile: store.GoModuleProfile, Module: c.Module, Version: c.Version, Digests: map[string]string{"zip": zipObject.Digest, "mod": modObject.Digest, "info": infoObject.Digest}}
	raw, _ := json.Marshal(metadata)
	as := []store.Artifact{{Path: c.Prefix() + ".zip", Digest: zipObject.Digest, Size: zipObject.Size, MediaType: "application/zip", Metadata: raw}, {Path: c.Prefix() + ".mod", Digest: modObject.Digest, Size: modObject.Size, MediaType: "text/plain; charset=utf-8", Metadata: raw}, {Path: c.Prefix() + ".info", Digest: infoObject.Digest, Size: infoObject.Size, MediaType: "application/json", Metadata: raw}}
	result, e := s.DB.PublishGoModule(r.Context(), i, repo.Name, as, r.Header.Get("Idempotency-Key"))
	if e != nil {
		respondErr(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	w.Write(result.Body)
}

// Go's protocol requires text/plain errors, including errors before repository
// dispatch. Successful artifact bytes still stream through the common writer.
type goProtocolResponse struct {
	http.ResponseWriter
	status int
}

func (w *goProtocolResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	if status >= 400 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Del("Content-Length")
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *goProtocolResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.status >= 400 {
		var failure struct{ Error struct{ Code, Action string } }
		if json.Unmarshal(p, &failure) == nil && failure.Error.Code != "" {
			body := []byte(failure.Error.Code + ": " + failure.Error.Action + "\n")
			n, e := w.ResponseWriter.Write(body)
			if e == nil && n != len(body) {
				e = io.ErrShortWrite
			}
			if e != nil {
				return 0, e
			}
			return len(p), nil
		}
	}
	return w.ResponseWriter.Write(p)
}
