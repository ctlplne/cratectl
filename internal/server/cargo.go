// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/cargo"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

var cargoToken = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

type cargoProtocolResponse struct{ http.ResponseWriter }

func (w cargoProtocolResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func cargoCredential(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !cargoToken.MatchString(values[0]) {
		return "", store.ErrUnauthenticated
	}
	return values[0], nil
}

func (s *Server) cargo(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if repo.Mode != "hosted" {
		fail(w, 405, "cargo_mode_unavailable", "Use a hosted Cargo repository.")
		return
	}
	root := s.PublicURL + "/cargo/" + repo.Name
	switch {
	case p == "api/v1/crates/new":
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			fail(w, 405, "method_not_allowed", "Publish with cargo publish.")
			return
		}
		if !s.cargoPublicAuthority(w) {
			return
		}
		s.cargoPublish(w, r, i, repo, "sparse+"+root+"/index/")
	case strings.HasPrefix(p, "api/v1/crates/"):
		action := strings.TrimPrefix(p, "api/v1/crates/")
		if name, rest, ok := strings.Cut(action, "/"); ok && rest == "owners" {
			s.cargoOwners(w, r, i, repo, name)
			return
		}
		s.cargoYank(w, r, i, repo, action)
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Read the sparse index and crate archives with GET or HEAD.")
	case p == "api/v1/crates":
		s.cargoSearch(w, r, i, repo)
	case p == "index/config.json":
		if s.cargoPublicAuthority(w) {
			writeJSON(w, 200, map[string]any{"api": root, "dl": root + "/download/{crate}/{version}", "auth-required": true})
		}
	case strings.HasPrefix(p, "index/"):
		s.cargoIndex(w, r, i, repo, strings.TrimPrefix(p, "index/"))
	case strings.HasPrefix(p, "download/"):
		s.cargoDownload(w, r, i, repo, strings.TrimPrefix(p, "download/"))
	default:
		respondErr(w, store.ErrNotFound)
	}
}

func (s *Server) cargoOwners(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, name string) {
	switch r.Method {
	case http.MethodGet:
		owners, err := s.DB.CargoOwners(r.Context(), i, repo.Name, name)
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"users": owners})
	case http.MethodPut, http.MethodDelete:
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail(w, 415, "cargo_owners_content_type", "Send Cargo owner changes as application/json.")
			return
		}
		var request struct {
			Users []string `json:"users"`
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		if err != nil || !decodeManagement(body, &request) {
			fail(w, 400, "cargo_owners_input", "Supply one Cargo owner request with up to 32 tenant actor names.")
			return
		}
		err = s.DB.ChangeCargoOwners(r.Context(), i, repo.Name, name, request.Users, r.Method == http.MethodPut)
		if errors.Is(err, cargo.ErrInput) {
			fail(w, 400, "cargo_owners_input", "Supply one Cargo owner request with up to 32 distinct tenant actor names.")
			return
		}
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "msg": "Cargo ownership updated."})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		fail(w, 405, "method_not_allowed", "Use cargo owner to list, add, or remove crate owners.")
	}
}

func (s *Server) cargoSearch(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository) {
	const advice = "Supply one crate name query and a result limit from 1 to 100."
	if len(r.URL.RawQuery) > 2048 {
		fail(w, 400, "cargo_search_query", advice)
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["q"]) != 1 || len(values["per_page"]) > 1 {
		fail(w, 400, "cargo_search_query", advice)
		return
	}
	limit := 10
	if values.Has("per_page") {
		limit, err = strconv.Atoi(values.Get("per_page"))
		if err != nil {
			fail(w, 400, "cargo_search_query", advice)
			return
		}
	}
	hits, total, err := s.DB.CargoSearch(r.Context(), i, repo.Name, values.Get("q"), limit)
	if errors.Is(err, cargo.ErrInput) {
		fail(w, 400, "cargo_search_query", advice)
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"crates": hits, "meta": map[string]int{"total": total}})
}

func (s *Server) cargoYank(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	parts := strings.Split(p, "/")
	if len(parts) != 3 || (parts[2] != "yank" && parts[2] != "unyank") {
		respondErr(w, store.ErrNotFound)
		return
	}
	yanked := parts[2] == "yank"
	method := http.MethodPut
	if yanked {
		method = http.MethodDelete
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(w, 405, "method_not_allowed", "Use cargo yank or cargo yank --undo.")
		return
	}
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 0)); err != nil {
		fail(w, 400, "cargo_yank_body", "Send the package and version in the endpoint with an empty body.")
		return
	}
	err := s.DB.SetCargoYanked(r.Context(), i, repo.Name, parts[0], parts[1], yanked)
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) cargoPublicAuthority(w http.ResponseWriter) bool {
	u, err := url.Parse(s.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		fail(w, 503, "public_url_required", "Configure the registry's public HTTPS URL for authenticated Cargo clients.")
		return false
	}
	return true
}

func (s *Server) cargoIndex(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	name := path.Base(p)
	expected, err := cargo.IndexPath(name)
	if err != nil || expected != p {
		respondErr(w, store.ErrNotFound)
		return
	}
	data, err := s.DB.CargoIndex(r.Context(), i, repo.Name, name, s.NativeVersionLimit, s.NativeMetadataBytes)
	if err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(data)+`"`)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func (s *Server) cargoDownload(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	name, version, ok := strings.Cut(p, "/")
	key, err := cargo.ArtifactPath(name, version)
	if !ok || err != nil {
		respondErr(w, store.ErrNotFound)
		return
	}
	resolved, err := s.resolve(r.Context(), i, repo, key, false)
	if err != nil {
		respondErr(w, err)
		return
	}
	entry, err := store.CargoArtifactEntry(resolved.artifact)
	if err != nil {
		fail(w, 503, "invalid_cargo_metadata", "Ask the operator to inspect this stored Cargo archive binding.")
		return
	}
	if !strings.EqualFold(entry.Name, name) || entry.Version != version {
		respondErr(w, store.ErrNotFound)
		return
	}
	s.serveResolvedArtifact(w, r, i, resolved)
}

func (s *Server) cargoPublish(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, sparseIndex string) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/octet-stream" {
		fail(w, 415, "cargo_content_type", "Send a Cargo publish frame as application/octet-stream.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	const maxBody = cargo.MaxUploadBytes + cargo.MaxMetadataBytes + 8
	if r.ContentLength > maxBody {
		s.cargoInputError(w, cargo.ErrLimit)
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxBody)
	defer body.Close()
	coordinate, size, err := cargo.ReadPublish(body)
	if err != nil {
		s.cargoInputError(w, err)
		return
	}
	obj, err := s.Blobs.Put(ctx, i.Tenant, io.LimitReader(body, size), "", size)
	if err != nil {
		respondErr(w, err)
		return
	}
	var extra [1]byte
	if _, err = io.ReadFull(body, extra[:]); err != io.EOF {
		s.cargoInputError(w, cargo.ErrInput)
		return
	}
	staged, err := s.Blobs.OpenVerified(ctx, i.Tenant, obj.Digest, obj.Size)
	if err != nil {
		respondErr(w, err)
		return
	}
	defer staged.Close()
	entry, err := cargo.ReadArchive(ctx, staged, coordinate, sparseIndex)
	if err != nil {
		s.cargoInputError(w, err)
		return
	}
	key, _ := cargo.ArtifactPath(coordinate.Name, coordinate.Version)
	if err = s.DB.PublishCargo(ctx, i, repo.Name, store.Artifact{
		Path: key, Digest: obj.Digest, Size: obj.Size, MediaType: cargo.MediaType,
	}, entry); err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"warnings": map[string][]string{"invalid_categories": {}, "invalid_badges": {}, "other": {}}})
}

func (s *Server) cargoInputError(w http.ResponseWriter, err error) {
	if errors.Is(err, cargo.ErrLimit) {
		fail(w, 413, "cargo_limit", "Reduce the Cargo archive or metadata to fit the registry's package bounds.")
		return
	}
	fail(w, 400, "invalid_cargo_package", "Send one Cargo publish frame whose name and version match its bounded registry-only Cargo.toml.")
}
