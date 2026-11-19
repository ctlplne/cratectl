// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/cran"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) cran(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, request string) {
	if archive, found := strings.CutPrefix(request, cran.ArchiveDirectory); found {
		s.serveCRANArchive(w, r, i, repo, archive)
		return
	}
	if name, found := strings.CutPrefix(request, cran.SourceDirectory); found && (name == "PACKAGES" || name == "PACKAGES.gz") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, 405, "method_not_allowed", "Read the CRAN source index with GET or HEAD.")
			return
		}
		s.serveCRANIndex(w, r, i, repo.Name, name)
		return
	}
	coordinate, ok := cran.ParsePath(request)
	if !ok {
		respondErr(w, store.ErrNotFound)
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.publishCRAN(w, r, i, repo.Name, coordinate)
	case http.MethodGet, http.MethodHead:
		s.serveCRANPackage(w, r, i, repo, request)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		fail(w, 405, "method_not_allowed", "Publish a CRAN source archive with PUT or consume it with GET or HEAD.")
	}
}

func (s *Server) serveCRANPackage(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, path string) {
	resolved, err := s.resolve(r.Context(), i, repo, path, false)
	if err == nil {
		_, err = store.ValidateCRANArtifact(resolved.artifact)
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	s.serveResolvedArtifact(w, r, i, resolved)
}

func (s *Server) serveCRANArchive(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, request string) {
	name, file, directory := strings.Cut(request, "/")
	if !directory || !cran.ValidName(name) {
		respondErr(w, store.ErrNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Publish original CRAN source archives under src/contrib.")
		return
	}
	if file != "" {
		path := cran.SourceDirectory + file
		coordinate, valid := cran.ParsePath(path)
		if !valid || coordinate.Name != name {
			respondErr(w, store.ErrNotFound)
			return
		}
		s.serveCRANPackage(w, r, i, repo, path)
		return
	}
	versions, err := s.DB.CRANArchivedVersions(r.Context(), i, repo.Name, name, s.NativeVersionLimit)
	if err != nil {
		respondErr(w, err)
		return
	}
	const first = "<!doctype html>\n<meta charset=\"utf-8\">\n<title>CRAN source archives</title>\n<ul>\n"
	const last = "</ul>\n"
	if int64(len(first)+len(last)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	var out strings.Builder
	out.WriteString(first)
	for _, version := range versions {
		file := name + "_" + version + ".tar.gz"
		// Only the constrained archive coordinate appears in the listing.
		entry := `<li><a href="` + file + `">` + file + "</a></li>\n"
		if int64(out.Len()+len(entry)+len(last)) > s.NativeMetadataBytes {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
		out.WriteString(entry)
	}
	out.WriteString(last)
	body := out.String()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest([]byte(body))+`"`)
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(body))
}

func (s *Server) serveCRANIndex(w http.ResponseWriter, r *http.Request, i store.Identity, repo, name string) {
	index, err := s.DB.CRANPackageIndex(r.Context(), i, repo, s.NativeVersionLimit, s.NativeMetadataBytes)
	if err != nil {
		respondErr(w, err)
		return
	}
	media := "text/plain; charset=utf-8"
	body := []byte(index)
	if name == "PACKAGES.gz" {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		_, err := writer.Write(body)
		if closeErr := writer.Close(); err != nil || closeErr != nil {
			respondErr(w, errors.Join(err, closeErr))
			return
		}
		body, media = compressed.Bytes(), "application/gzip"
		if int64(len(body)) > s.NativeMetadataBytes {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(body)+`"`)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

func (s *Server) publishCRAN(w http.ResponseWriter, r *http.Request, i store.Identity, repo string, c cran.Coordinate) {
	if r.ContentLength > cran.MaxArchiveBytes {
		fail(w, 413, "cran_archive_budget", "Reduce the CRAN tar.gz archive within the upload limit.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	checksum := crypt.CompatibilityHash("md5")
	body := io.TeeReader(http.MaxBytesReader(w, r.Body, cran.MaxArchiveBytes), checksum)
	object, err := s.Blobs.Put(ctx, i.Tenant, body, "", r.ContentLength)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(w, 413, "cran_archive_budget", "Reduce the CRAN tar.gz archive within the upload limit.")
			return
		}
		respondErr(w, err)
		return
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		respondErr(w, err)
		return
	}
	metadata, err := cran.Inspect(ctx, file, object.Size, c)
	file.Close()
	if ctx.Err() != nil {
		respondErr(w, ctx.Err())
		return
	}
	if errors.Is(err, cran.ErrPackage) {
		fail(w, 400, "invalid_cran_archive", "Supply a bounded R source archive whose DESCRIPTION matches the requested package name and version.")
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	encoded, err := json.Marshal(store.CRANPackage{Description: metadata, MD5: hex.EncodeToString(checksum.Sum(nil)), Validated: true})
	if err != nil {
		respondErr(w, err)
		return
	}
	if err := s.DB.PublishCRAN(ctx, i, repo, store.Artifact{Path: c.Path(), Digest: object.Digest, Size: object.Size,
		MediaType: store.CRANMedia, Metadata: encoded}); err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("X-Checksum-Sha256", object.Digest)
	w.WriteHeader(http.StatusCreated)
}
