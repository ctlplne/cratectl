// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

type npmSelected struct {
	Version store.NPMVersion
	Source  store.Repository
}

func npmMerge(members []store.NPMMember) (map[string]npmSelected, map[string]string) {
	versions := map[string]npmSelected{}
	tags := map[string]string{}
	seenTags := map[string]bool{}
	for _, member := range members {
		for _, v := range member.Versions {
			if _, seen := versions[v.Version]; !seen {
				versions[v.Version] = npmSelected{v, member.Repository}
			}
		}
		for tag, version := range member.Tags {
			if seenTags[tag] {
				continue
			}
			seenTags[tag] = true
			if v, ok := versions[version]; ok && v.Source.Name == member.Repository.Name && !v.Version.Blocked {
				tags[tag] = version
			}
		}
	}
	return versions, tags
}
func (s *Server) npmMembers(ctx context.Context, i store.Identity, repo store.Repository, name string, force bool) ([]store.NPMMember, error) {
	repositories, e := s.DB.NPMRepositories(ctx, i, repo.Name, name)
	if e != nil {
		return nil, e
	}
	for _, source := range repositories {
		if source.Mode != "proxy" {
			continue
		}
		_, e = s.resolveProxy(ctx, i, source, store.NPMCatalogPath(name), force)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
	}
	return s.DB.NPMView(ctx, i, repo.Name, name, s.NativeVersionLimit, s.NativeTagLimit, s.NativeMetadataBytes)
}
func npmDownloadPath(endpoint, name string, selected npmSelected) string {
	if selected.Source.Mode == "proxy" {
		return "/npm/" + endpoint + "/" + name + "/-/cratectl/" + selected.Source.Name + "/proxy/" + selected.Version.Key + ".tgz"
	}
	return "/npm/" + endpoint + "/" + name + "/-/cratectl/" + selected.Source.Name + "/hosted/" + selected.Version.Version + ".tgz"
}
func (s *Server) npmRemote(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if len(p) > 2048 {
		fail(w, 400, "invalid_path", "Use an npm path within the configured protocol safety budget.")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, "read_only_repository", "Publish to a hosted npm source.")
		return
	}
	if p == "-/ping" {
		writeJSON(w, 200, map[string]string{})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if marker := strings.Index(p, "/-/cratectl/"); marker >= 0 {
		name := p[:marker]
		parts := strings.Split(p[marker+len("/-/cratectl/"):], "/")
		if !npmName.MatchString(name) || len(name) > 214 || len(parts) != 3 || !store.Name.MatchString(parts[0]) || !strings.HasSuffix(parts[2], ".tgz") {
			respondErr(w, store.ErrNotFound)
			return
		}
		value := strings.TrimSuffix(parts[2], ".tgz")
		selected := npmSelected{Source: store.Repository{Name: parts[0], Mode: parts[1]}}
		switch parts[1] {
		case "proxy":
			if len(value) != 64 {
				respondErr(w, store.ErrNotFound)
				return
			}
			if _, e := hex.DecodeString(value); e != nil {
				respondErr(w, store.ErrNotFound)
				return
			}
			selected.Version.Key = value
		case "hosted":
			if !validNPMVersion(value) {
				respondErr(w, store.ErrNotFound)
				return
			}
			selected.Version.Version = value
		default:
			respondErr(w, store.ErrNotFound)
			return
		}
		s.serveNPMDownload(w, r, i, repo, name, selected)
		return
	}
	// Conventional version paths also provide governed intake for review-required
	// repositories. Metadata remains hidden until those bytes are approved.
	if marker := strings.Index(p, "/-/"); marker >= 0 {
		name := p[:marker]
		filename := p[marker+3:]
		version := strings.TrimSuffix(strings.TrimPrefix(filename, name+"-"), ".tgz")
		if !npmName.MatchString(name) || !validNPMVersion(version) || p != store.NPMPath(name, version) {
			respondErr(w, store.ErrNotFound)
			return
		}
		members, e := s.npmMembers(ctx, i, repo, name, forceRefresh(r))
		if e != nil {
			respondErr(w, e)
			return
		}
		versions, _ := npmMerge(members)
		selected, ok := versions[version]
		if !ok {
			respondErr(w, store.ErrNotFound)
			return
		}
		s.serveNPMDownload(w, r, i, repo, name, selected)
		return
	}
	tagsOnly := false
	if strings.HasPrefix(p, "-/package/") && strings.HasSuffix(p, "/dist-tags") {
		p = strings.TrimSuffix(strings.TrimPrefix(p, "-/package/"), "/dist-tags")
		tagsOnly = true
	}
	name, selector, ok := npmCoordinate(p)
	if !ok {
		fail(w, 400, "invalid_package", "Use an npm package name and optional version or tag.")
		return
	}
	members, e := s.npmMembers(ctx, i, repo, name, forceRefresh(r))
	if e != nil {
		respondErr(w, e)
		return
	}
	selected, tags := npmMerge(members)
	versions := map[string]any{}
	for version, selection := range selected {
		if selection.Version.Blocked {
			continue
		}
		var pkg map[string]any
		if json.Unmarshal(selection.Version.Package, &pkg) != nil || pkg["name"] != name || pkg["version"] != version {
			respondErr(w, store.ErrConflict)
			return
		}
		dist, ok := pkg["dist"].(map[string]any)
		if !ok {
			respondErr(w, store.ErrConflict)
			return
		}
		if pkg["bin"] != nil {
			pkg["bin"] = npmGraphField(pkg, "bin")
		}
		dist["tarball"] = s.url(npmDownloadPath(repo.Name, name, selection))
		versions[version] = pkg
	}
	if len(versions) == 0 {
		respondErr(w, store.ErrNotFound)
		return
	}
	var response any = map[string]any{"name": name, "versions": versions, "dist-tags": tags}
	if tagsOnly {
		response = tags
	} else if selector != "" {
		version := selector
		if target, ok := tags[selector]; ok {
			version = target
		}
		response = versions[version]
		if response == nil {
			respondErr(w, store.ErrNotFound)
			return
		}
	}
	encoded, _ := json.Marshal(response)
	if int64(len(encoded)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(encoded)+`"`)
	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "package.json", time.Time{}, bytes.NewReader(encoded))
}
func (s *Server) serveNPMDownload(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, name string, selected npmSelected) {
	members, e := s.DB.NPMRepositories(r.Context(), i, repo.Name, name)
	if e != nil {
		respondErr(w, e)
		return
	}
	var source store.Repository
	for _, member := range members {
		if member.Name == selected.Source.Name && member.Mode == selected.Source.Mode {
			source = member
			break
		}
	}
	if source.Name == "" {
		respondErr(w, store.ErrDenied)
		return
	}
	p := store.NPMPath(name, selected.Version.Version)
	if source.Mode == "proxy" {
		binding, e := s.DB.NPMSource(r.Context(), i, source.Name, selected.Version.Key)
		if e != nil {
			respondErr(w, e)
			return
		}
		if binding.Name != name {
			respondErr(w, store.ErrNotFound)
			return
		}
		p = store.NPMBlobPath(name, binding.Key)
	}
	resolved, e := s.resolve(r.Context(), i, source, p, forceRefresh(r))
	if e != nil {
		respondErr(w, e)
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
	s.serveResolvedArtifact(w, r, i, resolved)
}
