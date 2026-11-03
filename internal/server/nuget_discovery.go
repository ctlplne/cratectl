// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) nugetRoot(repo string) (string, error) {
	u, e := url.Parse(s.PublicURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", store.ErrConfigurationInput
	}
	return s.PublicURL + "/nuget/" + repo + "/", nil
}

func nugetRegistrationURL(root, id string) string {
	return root + "registration/" + url.PathEscape(id) + "/"
}

func nugetOptionalProperties(out map[string]any, p map[string]string) {
	for _, name := range []string{"authors", "description", "title", "summary", "tags", "language"} {
		if value := p[name]; value != "" {
			out[name] = value
		}
	}
	for _, name := range []string{"projectUrl", "licenseUrl", "iconUrl"} {
		value := p[strings.ToLower(name)]
		u, e := url.Parse(value)
		if e == nil && u.Host != "" && u.User == nil && (u.Scheme == "http" || u.Scheme == "https") {
			out[name] = value
		}
	}
}

func registrationEntry(ctx context.Context, root string, a store.Artifact) (string, map[string]any, map[string]any, error) {
	m, e := store.ValidateNuGetArtifact(ctx, a)
	if e != nil {
		return "", nil, nil, e
	}
	c, e := nuget.BuildCatalog(ctx, m.Nuspec)
	if e != nil {
		return "", nil, nil, e
	}
	d, e := nuget.ParseNuspecDependencies(ctx, m.Nuspec)
	if e != nil {
		return "", nil, nil, e
	}
	base := nugetRegistrationURL(root, m.IDKey)
	leaf := base + url.PathEscape(m.VersionKey) + ".json"
	content := root + "flat/" + url.PathEscape(m.IDKey) + "/" + url.PathEscape(m.VersionKey) + "/" + url.PathEscape(m.IDKey+"."+m.VersionKey+".nupkg")
	published := a.Created.UTC().Format(time.RFC3339Nano)
	if !m.IsListed() {
		published = "1900-01-01T00:00:00Z"
	}
	catalog := map[string]any{"@id": base + url.PathEscape(m.VersionKey) + "/catalog.json", "id": m.ID, "version": c.Version, "listed": m.IsListed(), "published": published, "packageContent": content, "requireLicenseAcceptance": strings.EqualFold(c.Values["requirelicenseacceptance"], "true")}
	nugetOptionalProperties(catalog, c.Values)
	groups := []map[string]any{}
	for _, g := range d.Groups {
		deps := []map[string]string{}
		for _, dep := range g.Dependencies {
			rangeText := dep.RawRange
			if strings.TrimSpace(rangeText) == "*" {
				rangeText = "[0.0.0, )"
			}
			deps = append(deps, map[string]string{"id": dep.ID, "range": rangeText, "registration": nugetRegistrationURL(root, dep.IDKey) + "index.json"})
		}
		group := map[string]any{"dependencies": deps}
		if g.TargetFramework != "" {
			group["targetFramework"] = g.TargetFramework
		}
		groups = append(groups, group)
	}
	catalog["dependencyGroups"] = groups
	entry := map[string]any{"@id": leaf, "catalogEntry": catalog, "packageContent": content, "registration": base + "index.json"}
	return m.VersionKey, catalog, entry, nil
}

func (s *Server) nugetRegistration(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p, root string) {
	parts := strings.Split(strings.TrimPrefix(p, "registration/"), "/")
	if len(parts) != 2 && len(parts) != 3 {
		respondErr(w, store.ErrNotFound)
		return
	}
	id, e := nuget.IDKey(parts[0])
	if e != nil || id != parts[0] {
		respondErr(w, store.ErrNotFound)
		return
	}
	index := len(parts) == 2 && parts[1] == "index.json"
	version := ""
	if !index {
		v := parts[1]
		if len(parts) == 2 {
			if !strings.HasSuffix(v, ".json") {
				respondErr(w, store.ErrNotFound)
				return
			}
			v = strings.TrimSuffix(v, ".json")
		} else if parts[2] != "catalog.json" {
			respondErr(w, store.ErrNotFound)
			return
		}
		version, e = nuget.VersionKey(v)
		if e != nil || version != v {
			respondErr(w, store.ErrNotFound)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var artifacts []store.Artifact
	if index {
		artifacts, e = s.DB.NuGetRegistration(ctx, i, repo.Name, id, s.NativeVersionLimit, s.NativeMetadataBytes)
	} else {
		var a store.Artifact
		a, e = s.DB.NuGetRegistrationVersion(ctx, i, repo.Name, id, version, s.NativeMetadataBytes)
		artifacts = []store.Artifact{a}
	}
	if e != nil {
		respondErr(w, e)
		return
	}
	if len(artifacts) == 0 {
		respondErr(w, store.ErrNotFound)
		return
	}
	byVersion := map[string]map[string]any{}
	keys := []string{}
	remaining := s.NativeMetadataBytes
	for _, a := range artifacts {
		key, catalog, entry, err := registrationEntry(ctx, root, a)
		if err != nil {
			respondErr(w, err)
			return
		}
		if !index {
			if len(parts) == 3 {
				s.nugetGzipJSON(w, r, catalog)
				return
			}
			leaf := map[string]any{"@id": entry["@id"], "catalogEntry": catalog["@id"], "listed": catalog["listed"], "published": catalog["published"], "packageContent": entry["packageContent"], "registration": entry["registration"]}
			s.nugetGzipJSON(w, r, leaf)
			return
		}
		encoded, err := json.Marshal(entry)
		remaining -= int64(len(encoded) + 512)
		if err != nil || remaining < 0 {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
		byVersion[key] = entry
		keys = append(keys, key)
	}
	keys, e = nuget.SortVersionKeys(ctx, keys)
	if e != nil {
		respondErr(w, e)
		return
	}
	base := nugetRegistrationURL(root, id) + "index.json"
	pages := []map[string]any{}
	for start := 0; start < len(keys); start += 64 {
		end := min(start+64, len(keys))
		leaves := []map[string]any{}
		for _, key := range keys[start:end] {
			leaves = append(leaves, byVersion[key])
		}
		pages = append(pages, map[string]any{"@id": base + "#page/" + url.PathEscape(keys[start]) + "/" + url.PathEscape(keys[end-1]), "count": len(leaves), "lower": keys[start], "upper": keys[end-1], "parent": base, "items": leaves})
	}
	s.nugetGzipJSON(w, r, map[string]any{"@id": base, "count": len(pages), "items": pages})
}

// Resource3.6.0 is always gzip encoded. The ETag identifies the actual compressed
// representation; HEAD, ranges and conditional requests use the same bytes.
func (s *Server) nugetGzipJSON(w http.ResponseWriter, r *http.Request, value any) {
	data, e := json.Marshal(value)
	if e != nil || int64(len(data)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, e = z.Write(data); e != nil {
		respondErr(w, e)
		return
	}
	if e = z.Close(); e != nil {
		respondErr(w, e)
		return
	}
	if int64(out.Len()) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(out.Bytes())+`"`)
	http.ServeContent(w, r, "registration.json", time.Time{}, bytes.NewReader(out.Bytes()))
}

func parseNuGetSearch(r *http.Request) (store.NuGetSearchRequest, error) {
	q := store.NuGetSearchRequest{Take: 20}
	values, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(r.URL.RawQuery) > 4096 {
		return q, store.ErrConfigurationInput
	}
	for key, v := range values {
		if len(v) != 1 {
			return q, store.ErrConfigurationInput
		}
		switch key {
		case "q":
			q.Query = v[0]
		case "skip":
			q.Skip, e = strconv.Atoi(v[0])
		case "take":
			q.Take, e = strconv.Atoi(v[0])
		case "prerelease":
			if v[0] != "true" && v[0] != "false" {
				return q, store.ErrConfigurationInput
			}
			q.Prerelease = v[0] == "true"
		case "semVerLevel":
			var order int
			order, e = nuget.CompareVersions(v[0], "2.0.0")
			q.SemVer2 = order >= 0
		case "packageType":
			if v[0] != "" {
				return q, store.ErrConfigurationInput
			}
		default: // Additional client hints have no bearing on this resource version.
		}
		if e != nil {
			return q, store.ErrConfigurationInput
		}
	}
	if !q.Valid() {
		return q, store.ErrConfigurationInput
	}
	return q, nil
}

func (s *Server) nugetSearch(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, root string) {
	q, e := parseNuGetSearch(r)
	if e != nil {
		respondErr(w, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	items, total, e := s.DB.NuGetSearch(ctx, i, repo.Name, q, s.NativeVersionLimit, s.NativeMetadataBytes)
	if e != nil {
		respondErr(w, e)
		return
	}
	data := []map[string]any{}
	for _, item := range items {
		base := nugetRegistrationURL(root, item.IDKey)
		result := map[string]any{"id": item.Catalog.Values["id"], "version": item.Catalog.Version, "registration": base + "index.json"}
		nugetOptionalProperties(result, item.Catalog.Values)
		versions := []map[string]any{}
		for _, v := range item.Versions {
			key, _ := nuget.VersionKey(v)
			versions = append(versions, map[string]any{"version": v, "@id": base + url.PathEscape(key) + ".json", "downloads": 0})
		}
		result["versions"] = versions
		data = append(data, result)
	}
	s.nugetJSON(w, r, map[string]any{"totalHits": total, "data": data})
}
