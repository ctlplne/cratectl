// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"mime"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

type pythonSelected struct {
	File   store.PythonFileView
	Source store.Repository
}

func pythonMerge(members []store.PythonMember) map[string]pythonSelected {
	out := map[string]pythonSelected{}
	for _, member := range members {
		for _, file := range member.Files {
			if _, exists := out[file.File.Filename]; !exists {
				out[file.File.Filename] = pythonSelected{file, member.Repository}
			}
		}
	}
	return out
}
func (s *Server) pythonMembers(ctx context.Context, i store.Identity, repo store.Repository, name string, force bool) ([]store.PythonMember, error) {
	members, e := s.DB.NativeRepositories(ctx, i, repo.Name, name, "pypi")
	if e != nil {
		return nil, e
	}
	for _, member := range members {
		if member.Mode == "proxy" {
			_, e = s.resolveProxy(ctx, i, member, store.PythonCatalogPath(name), force)
			if e != nil && !errors.Is(e, store.ErrNotFound) {
				return nil, e
			}
		}
	}
	return s.DB.PythonView(ctx, i, repo.Name, name, s.NativeVersionLimit, s.NativeMetadataBytes)
}
func pythonPrefersJSON(accept string) (bool, error) {
	if len(accept) > 4096 {
		return false, errPythonIndex
	}
	if accept == "" {
		return false, nil
	}
	jsonQ, htmlQ := -1.0, -1.0
	for _, part := range strings.Split(accept, ",") {
		media, parameters, e := mime.ParseMediaType(strings.TrimSpace(part))
		if e != nil {
			return false, e
		}
		q := 1.0
		if raw, ok := parameters["q"]; ok {
			q, e = strconv.ParseFloat(raw, 64)
			if e != nil || q != q || q < 0 || q > 1 {
				return false, errPythonIndex
			}
		}
		switch media {
		case "application/vnd.pypi.simple.v1+json", "application/json":
			jsonQ = max(jsonQ, q)
		case "text/html", "application/vnd.pypi.simple.v1+html", "*/*":
			htmlQ = max(htmlQ, q)
		}
	}
	if jsonQ <= 0 && htmlQ <= 0 {
		return false, errPythonIndex
	}
	return jsonQ > 0 && jsonQ >= htmlQ, nil
}
func pythonFileURL(endpoint string, selected pythonSelected) string {
	key := selected.File.Key
	if selected.Source.Mode == "hosted" {
		key = selected.File.Digest
	}
	return "/pypi/" + endpoint + "/files/" + selected.Source.Name + "/" + selected.Source.Mode + "/" + key + "/" + segment(selected.File.File.Filename)
}
func pythonCoreAdvertised(file store.PythonFile) any {
	if !file.CoreAvailable {
		return false
	}
	if file.CoreSHA256 != "" {
		return map[string]string{"sha256": file.CoreSHA256}
	}
	if file.CoreIntegrity != "" {
		pin, e := crypt.ParseSourceIntegrity(file.CoreIntegrity, "", false)
		if e == nil {
			return pin.HexHashes()
		}
	}
	return true
}
func (s *Server) pythonSimple(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, "method_not_allowed", "Publish with twine or resolve with pip.")
		return
	}
	if len(p) > 2048 || (!strings.HasPrefix(p, "simple/") && p != "simple") {
		fail(w, 404, "not_found", "Configure the /simple/ Python index URL.")
		return
	}
	project := strings.Trim(strings.TrimPrefix(p, "simple"), "/")
	if project != "" && (!pyName.MatchString(project) || len(project) > 200) {
		fail(w, 400, "invalid_project", "Use a valid Python project name.")
		return
	}
	project = NormalizePython(project)
	canonical := "simple/"
	if project != "" {
		canonical += project + "/"
	}
	if p != canonical {
		http.Redirect(w, r, s.url("/pypi/"+repo.Name+"/"+canonical), http.StatusMovedPermanently)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	jsonResponse, e := pythonPrefersJSON(r.Header.Get("Accept"))
	if e != nil {
		fail(w, 406, "not_acceptable", "Request the Python simple HTML or version 1 JSON representation.")
		return
	}
	w.Header().Set("Vary", "Accept")
	var response any
	var page bytes.Buffer
	if project == "" {
		names, e := s.DB.PythonProjects(ctx, i, repo.Name, s.NativeVersionLimit, s.NativeMetadataBytes)
		if e != nil {
			respondErr(w, e)
			return
		}
		sort.Strings(names)
		if jsonResponse {
			projects := []map[string]string{}
			for _, name := range names {
				projects = append(projects, map[string]string{"name": name})
			}
			response = map[string]any{"meta": map[string]string{"api-version": "1.0"}, "projects": projects}
		} else {
			page.WriteString("<!doctype html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"></head><body>\n")
			for _, name := range names {
				fmt.Fprintf(&page, "<a href=\"%s/\">%s</a><br>\n", html.EscapeString(name), html.EscapeString(name))
			}
			page.WriteString("</body></html>\n")
		}
	} else {
		members, e := s.pythonMembers(ctx, i, repo, project, forceRefresh(r))
		if e != nil {
			respondErr(w, e)
			return
		}
		selected := pythonMerge(members)
		filenames := []string{}
		for filename, file := range selected {
			if !file.File.Blocked {
				filenames = append(filenames, filename)
			}
		}
		sort.Strings(filenames)
		if len(filenames) == 0 {
			respondErr(w, store.ErrNotFound)
			return
		}
		files := []map[string]any{}
		allSizes := true
		page.WriteString("<!doctype html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"></head><body>\n")
		for _, filename := range filenames {
			selection := selected[filename]
			file := selection.File
			link := s.url(pythonFileURL(repo.Name, selection))
			hashes := map[string]string{}
			if file.Integrity != "" {
				pin, e := crypt.ParseSourceIntegrity(file.Integrity, "", false)
				if e != nil {
					respondErr(w, e)
					return
				}
				hashes = pin.HexHashes()
			}
			if file.Digest != "" {
				hashes["sha256"] = file.Digest
			}
			if len(hashes) == 0 {
				respondErr(w, store.ErrConflict)
				return
			}
			yanked := any(false)
			if file.File.Yanked != nil {
				if *file.File.Yanked == "" {
					yanked = true
				} else {
					yanked = *file.File.Yanked
				}
			}
			core := pythonCoreAdvertised(file.File)
			entry := map[string]any{"filename": filename, "url": link, "hashes": hashes, "requires-python": file.File.RequiresPython, "yanked": yanked, "core-metadata": core, "dist-info-metadata": core}
			if file.Size >= 0 {
				entry["size"] = file.Size
			} else if file.File.Size != nil {
				entry["size"] = *file.File.Size
			} else {
				allSizes = false
			}
			files = append(files, entry)
			pin, e := crypt.SourceIntegrityFromHex(hashes)
			if e != nil {
				respondErr(w, e)
				return
			}
			fragment := ""
			for algorithm, value := range pin.HexHashes() {
				fragment = algorithm + "=" + value
			}
			fmt.Fprintf(&page, "<a href=\"%s#%s\" data-requires-python=\"%s\"", html.EscapeString(link), fragment, html.EscapeString(file.File.RequiresPython))
			if file.File.Yanked != nil {
				fmt.Fprintf(&page, " data-yanked=\"%s\"", html.EscapeString(*file.File.Yanked))
			}
			if file.File.CoreAvailable {
				attr := "true"
				if hashes, ok := core.(map[string]string); ok {
					for algorithm, value := range hashes {
						attr = algorithm + "=" + value
					}
				}
				fmt.Fprintf(&page, " data-core-metadata=\"%s\" data-dist-info-metadata=\"%s\"", html.EscapeString(attr), html.EscapeString(attr))
			}
			fmt.Fprintf(&page, ">%s</a><br>\n", html.EscapeString(filename))
		}
		page.WriteString("</body></html>\n")
		apiVersion := "1.0"
		if allSizes {
			apiVersion = "1.1"
		}
		response = map[string]any{"meta": map[string]string{"api-version": apiVersion}, "name": project, "files": files}
	}
	encoded := page.Bytes()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if jsonResponse {
		encoded, e = json.Marshal(response)
		if e != nil {
			respondErr(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
	}
	if int64(len(encoded)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(encoded)+`"`)
	http.ServeContent(w, r, "index", time.Time{}, bytes.NewReader(encoded))
}
func (s *Server) pythonDownload(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, "method_not_allowed", "Read Python distributions through the index.")
		return
	}
	metadata := strings.HasSuffix(p, ".metadata")
	if metadata {
		p = strings.TrimSuffix(p, ".metadata")
	}
	if !ValidPath(p) {
		respondErr(w, store.ErrNotFound)
		return
	}
	parts := strings.Split(p, "/")
	filename := parts[len(parts)-1]
	name, _, _, e := pythonDistribution(filename)
	if e != nil {
		respondErr(w, store.ErrNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var selection pythonSelected
	if len(parts) == 1 {
		members, e := s.pythonMembers(ctx, i, repo, name, forceRefresh(r))
		if e != nil {
			respondErr(w, e)
			return
		}
		var ok bool
		selection, ok = pythonMerge(members)[filename]
		if !ok {
			respondErr(w, store.ErrNotFound)
			return
		}
	} else if len(parts) == 4 && store.Name.MatchString(parts[0]) && (parts[1] == "hosted" || parts[1] == "proxy") && len(parts[2]) == 64 {
		if _, e := hex.DecodeString(parts[2]); e != nil {
			respondErr(w, store.ErrNotFound)
			return
		}
		selection.Source = store.Repository{Name: parts[0], Mode: parts[1]}
		selection.File.Key = parts[2]
		selection.File.Digest = parts[2]
	} else {
		respondErr(w, store.ErrNotFound)
		return
	}
	members, e := s.DB.NativeRepositories(ctx, i, repo.Name, name, "pypi")
	if e != nil {
		respondErr(w, e)
		return
	}
	var source store.Repository
	for _, member := range members {
		if member.Name == selection.Source.Name && member.Mode == selection.Source.Mode {
			source = member
			break
		}
	}
	if source.Name == "" {
		respondErr(w, store.ErrDenied)
		return
	}
	artifactPath := filename
	if source.Mode == "proxy" {
		binding, e := s.DB.NativeSource(ctx, i, source.Name, selection.File.Key, "pypi")
		if e != nil {
			respondErr(w, e)
			return
		}
		if binding.Name != name || binding.Coordinate != filename {
			respondErr(w, store.ErrNotFound)
			return
		}
		artifactPath = store.PythonBlobPath(name, binding.Key, filename)
	}
	resolved, e := s.resolve(ctx, i, source, artifactPath, forceRefresh(r))
	if e != nil {
		respondErr(w, e)
		return
	}
	if source.Mode == "hosted" && len(parts) == 4 && resolved.artifact.Digest != parts[2] {
		respondErr(w, store.ErrConflict)
		return
	}
	if repo.RequireReview && resolved.artifact.Decision != "allowed" {
		respondErr(w, store.ErrDenied)
		return
	}
	if repo.Mode == "group" {
		resolved.groups = append(resolved.groups, repo.Name)
		resolved.groupRevisions = map[string]int64{repo.Name: repo.SourceRevision}
	}
	if !metadata {
		s.serveResolvedArtifact(w, r, i, resolved)
		return
	}
	var file store.PythonFile
	if json.Unmarshal(resolved.artifact.Metadata, &file) != nil || !file.Validated || !file.CoreAvailable {
		respondErr(w, store.ErrNotFound)
		return
	}
	parent, e := s.Blobs.OpenVerified(ctx, i.Tenant, resolved.artifact.Digest, resolved.artifact.Size)
	if e != nil {
		respondErr(w, e)
		return
	}
	parent.Close()
	if _, e = s.guardResolved(ctx, i, resolved); e != nil {
		respondErr(w, e)
		return
	}
	if int64(len(file.CoreMetadata)) > s.PythonMetadataBytes || crypt.Digest([]byte(file.CoreMetadata)) != file.CoreSHA256 {
		fail(w, 503, "integrity_failure", "Repair the exact parent distribution and its validated metadata.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Cratectl-Repository", source.Name)
	w.Header().Set("ETag", `"sha256:`+file.CoreSHA256+`"`)
	http.ServeContent(w, r, path.Base(filename)+".metadata", time.Time{}, strings.NewReader(file.CoreMetadata))
}
