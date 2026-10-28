// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/Masterminds/semver/v3"
	"io"
	"time"
)

var npmName = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

func validNPMVersion(v string) bool {
	if len(v) > 128 {
		return false
	}
	parsed, e := semver.StrictNewVersion(v)
	return e == nil && parsed.String() == v
}

var npmTagName = regexp.MustCompile(`^[A-Za-z0-9_.!~*'()+-]{1,128}$`)

func validNPMTag(tag string) bool {
	if !npmTagName.MatchString(tag) || tag == "." || tag == ".." {
		return false
	}
	_, e := semver.NewConstraint(tag)
	return e != nil
}

func (s *Server) npm(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if repo.Mode != "hosted" {
		s.npmRemote(w, r, i, repo, p)
		return
	}
	if strings.HasPrefix(p, "-/package/") {
		s.npmDistTags(w, r, i, repo, strings.TrimPrefix(p, "-/package/"))
		return
	}
	if p == "-/ping" {
		writeJSON(w, 200, map[string]string{})
		return
	}
	if strings.Contains(p, "/-/") {
		if !ValidPath(p) {
			fail(w, 400, "invalid_path", "Use a valid package path.")
			return
		}
		s.serveArtifact(w, r, i, repo.Name, p)
		return
	}
	name, selector, ok := npmCoordinate(p)
	if !ok {
		fail(w, 400, "invalid_package", "Use an npm package name and optional version or tag.")
		return
	}
	if !npmName.MatchString(name) || len(name) > 214 {
		fail(w, 400, "invalid_package", "Use a valid npm package name.")
		return
	}
	if r.Method == "PUT" {
		if selector != "" {
			fail(w, 400, "invalid_publish_path", "Publish to the package endpoint, without a version suffix.")
			return
		}
		var doc struct {
			Name        string                     `json:"name"`
			ID          string                     `json:"_id"`
			Description string                     `json:"description"`
			Versions    map[string]json.RawMessage `json:"versions"`
			DistTags    map[string]string          `json:"dist-tags"`
			Attachments map[string]struct {
				ContentType string `json:"content_type"`
				Data        string `json:"data"`
				Length      int64  `json:"length"`
			} `json:"_attachments"`
			Access string `json:"access"`
		}
		// npm adds metadata fields over time. Bound the document but accept unknown
		// fields here; the adapter only interprets the explicit publication fields.
		r.Body = http.MaxBytesReader(w, r.Body, s.NPMPublishBytes)
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&doc) != nil || doc.Name != name || len(doc.Versions) != 1 || len(doc.Attachments) != 1 {
			fail(w, 400, "invalid_npm_publish", "Publish one npm version and tarball within the configured npm publication budget.")
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			fail(w, 400, "invalid_json", "Send one publication document.")
			return
		}
		if len(doc.DistTags) > s.NativeTagLimit {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
		for tag, version := range doc.DistTags {
			if !validNPMTag(tag) || !validNPMVersion(version) {
				fail(w, 400, "invalid_dist_tag", "Use a named tag and canonical semantic target version.")
				return
			}
		}
		as := []store.Artifact{}
		for version, raw := range doc.Versions {
			if !validNPMVersion(version) {
				fail(w, 400, "invalid_version", "Use a semantic npm version.")
				return
			}
			var meta map[string]any
			if json.Unmarshal(raw, &meta) != nil || meta["name"] != name || meta["version"] != version {
				fail(w, 400, "metadata_mismatch", "Package metadata must match the published coordinate.")
				return
			}
			for filename, attachment := range doc.Attachments {
				expected := name + "-" + version + ".tgz"
				if filename != expected {
					fail(w, 400, "attachment_mismatch", "Use the npm-generated tarball name.")
					return
				}
				b, e := base64.StdEncoding.DecodeString(attachment.Data)
				if e != nil || int64(len(b)) != attachment.Length {
					fail(w, 400, "attachment_mismatch", "Check tarball encoding and length.")
					return
				}
				dist, ok := meta["dist"].(map[string]any)
				if !ok {
					dist = map[string]any{}
				}
				if sum, ok := dist["shasum"].(string); ok && sum != crypt.SHA1(b) {
					fail(w, 400, "checksum_mismatch", "Regenerate the package tarball.")
					return
				}
				if sum, ok := dist["integrity"].(string); ok && sum != crypt.Integrity(b) {
					fail(w, 400, "checksum_mismatch", "Regenerate the package tarball.")
					return
				}
				pkg, e := npmArchivePackage(b, name, version, s.NPMExpandedBytes, s.NPMFileLimit, s.NPMPackageJSONBytes)
				if e != nil {
					fail(w, 400, "invalid_npm_archive", "Regenerate the tarball: package/package.json must match the coordinate, paths and links must stay inside package/, and archive budgets must fit.")
					return
				}
				meta = pkg
				obj, e := s.Blobs.Put(r.Context(), i.Tenant, bytes.NewReader(b), "", int64(len(b)))
				if e != nil {
					respondErr(w, e)
					return
				}
				meta["dist"] = map[string]any{"shasum": crypt.SHA1(b), "integrity": crypt.Integrity(b)}
				// Store client-independent metadata; endpoint authority is generated from
				// configured public URL rather than an untrusted Host header.
				encoded, _ := json.Marshal(map[string]any{"name": name, "version": version, "package": meta, "dist_tags": doc.DistTags})
				as = append(as, store.Artifact{Path: name + "/-/" + filename, Digest: obj.Digest, Size: obj.Size, MediaType: "application/octet-stream", Metadata: encoded})
			}
		}
		if e := s.DB.PublishNPM(r.Context(), i, repo.Name, name, as, doc.DistTags, s.NativeTagLimit); e != nil {
			respondErr(w, e)
			return
		}
		writeJSON(w, 201, map[string]bool{"ok": true})
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, "method_not_allowed", "Use npm publish or metadata GET.")
		return
	}
	as, tags, e := s.DB.NPMState(r.Context(), i, repo.Name, name, s.NativeVersionLimit, s.NativeMetadataBytes, s.NativeTagLimit)
	if e != nil {
		respondErr(w, e)
		return
	}
	if len(as) == 0 {
		respondErr(w, store.ErrNotFound)
		return
	}
	versions := map[string]any{}
	for _, a := range as {
		var meta struct {
			Name     string            `json:"name"`
			Version  string            `json:"version"`
			Package  map[string]any    `json:"package"`
			DistTags map[string]string `json:"dist_tags"`
		}
		if json.Unmarshal(a.Metadata, &meta) != nil || meta.Name != name {
			continue
		}
		dist, ok := meta.Package["dist"].(map[string]any)
		if !ok {
			continue
		}
		dist["tarball"] = s.url("/npm/" + repo.Name + "/" + a.Path)
		if meta.Package["bin"] != nil {
			meta.Package["bin"] = npmGraphField(meta.Package, "bin")
		}
		versions[meta.Version] = meta.Package
	}
	for t, v := range tags {
		if versions[v] == nil {
			delete(tags, t)
		}
	}
	var response any = map[string]any{"name": name, "versions": versions, "dist-tags": tags}
	if selector != "" {
		version := selector
		if selected, exists := tags[selector]; exists {
			version = selected
		}
		response = versions[version]
		if response == nil {
			respondErr(w, store.ErrNotFound)
			return
		}
	}
	encoded, e := json.Marshal(response)
	if e != nil {
		respondErr(w, e)
		return
	}
	if int64(len(encoded)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	etag := `"sha256:` + crypt.Digest(encoded) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "package.json", time.Time{}, bytes.NewReader(encoded))
}

func (s *Server) npmDistTags(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	marker := strings.LastIndex(p, "/dist-tags")
	if marker < 0 {
		respondErr(w, store.ErrNotFound)
		return
	}
	name := p[:marker]
	if suffix := p[marker+len("/dist-tags"):]; suffix != "" && !strings.HasPrefix(suffix, "/") {
		respondErr(w, store.ErrNotFound)
		return
	}
	tail := strings.TrimPrefix(p[marker+len("/dist-tags"):], "/")
	if !npmName.MatchString(name) || len(name) > 214 {
		fail(w, 400, "invalid_package", "Use a valid npm package name.")
		return
	}
	if r.Method == "GET" && tail == "" {
		_, tags, e := s.DB.NPMState(r.Context(), i, repo.Name, name, s.NativeVersionLimit, s.NativeMetadataBytes, s.NativeTagLimit)
		if e != nil {
			respondErr(w, e)
			return
		}
		writeJSON(w, 200, tags)
		return
	}
	if !validNPMTag(tail) || (r.Method != "PUT" && r.Method != "DELETE") {
		fail(w, 400, "invalid_tag_operation", "Use npm dist-tag with a named tag.")
		return
	}
	version := ""
	if r.Method == "PUT" {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		if decoder.Decode(&version) != nil || !validNPMVersion(version) {
			fail(w, 400, "invalid_version", "Use a canonical semantic version.")
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			fail(w, 400, "invalid_json", "Send one version string.")
			return
		}
	}
	if e := s.DB.ChangeNPMTag(r.Context(), i, repo.Name, name, tail, version, r.Method == "DELETE", s.NativeTagLimit); e != nil {
		respondErr(w, e)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func npmCoordinate(p string) (string, string, bool) {
	p = strings.TrimSuffix(p, "/")
	parts := strings.Split(p, "/")
	count := 1
	if strings.HasPrefix(p, "@") {
		count = 2
	}
	if len(parts) < count || len(parts) > count+1 {
		return "", "", false
	}
	name := strings.Join(parts[:count], "/")
	selector := ""
	if len(parts) == count+1 {
		selector = parts[count]
		if !validNPMVersion(selector) && !validNPMTag(selector) {
			return "", "", false
		}
	}
	return name, selector, npmName.MatchString(name) && len(name) <= 214
}
