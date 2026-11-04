// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

type mavenDocument struct {
	model  mavenMetadata
	member store.MavenMember
}

var errMavenViewChanged = errors.New("Maven metadata changed during bounded admission")

type mavenVersionCandidate struct {
	blocked bool
	updated string
}
type mavenSnapshotCandidate struct {
	value   mavenSnapshotVersion
	blocked bool
}

func mavenSourceAllowed(group store.Repository, source, p string) bool {
	for _, name := range store.MembersForPath(group, p) {
		if source == name {
			return true
		}
	}
	return false
}
func mavenBlocked(a store.Artifact, review bool) bool {
	return a.Deleted || a.Decision == "denied" || review && a.Decision != "allowed"
}
func mavenSnapshotNewer(a, b mavenSnapshotVersion) bool {
	if a.Updated != b.Updated {
		return a.Updated > b.Updated
	}
	// Numeric build counters must not use lexical ordering (10 follows 9).
	left, right := strings.LastIndexByte(a.Value, '-'), strings.LastIndexByte(b.Value, '-')
	if left > 0 && right > 0 && a.Value[:left] == b.Value[:right] {
		x, _ := strconv.ParseUint(a.Value[left+1:], 10, 31)
		y, _ := strconv.ParseUint(b.Value[right+1:], 10, 31)
		return x > y
	}
	return a.Value > b.Value
}
func mavenSnapshotPath(dir, artifact string, v mavenSnapshotVersion) string {
	name := artifact + "-" + v.Value
	if v.Classifier != "" {
		name += "-" + v.Classifier
	}
	return dir + "/" + name + "." + v.Extension
}

func renderMavenMetadata(view store.MavenView, documents []mavenDocument, p string, limit int, maxBytes int64) ([]byte, error) {
	dir := path.Dir(p)
	out := mavenMetadata{Model: "1.1.0"}
	type firstMavenReference struct {
		artifact store.Artifact
		source   string
	}
	firstReferences := map[string]firstMavenReference{}
	for _, member := range view.Members {
		for _, a := range member.Artifacts {
			if !mavenSourceAllowed(view.Group, member.Repository.Name, a.Path) {
				continue
			}
			if _, exists := firstReferences[a.Path]; !exists {
				firstReferences[a.Path] = firstMavenReference{a, member.Repository.Name}
			}
		}
	}
	versions := map[string]mavenVersionCandidate{}
	snapshots := map[string]mavenSnapshotCandidate{}
	plugins := map[string]*mavenPlugin{}
	var latest, release, latestTime, releaseTime, updated string
	latestDocument, releaseDocument := -1, -1
	for documentIndex, document := range documents {
		md, member := document.model, document.member
		review := view.Group.RequireReview || member.Repository.RequireReview
		if md.Artifact != "" {
			out.Group, out.Artifact, out.Version = md.Group, md.Artifact, md.Version
		}
		v := md.Versioning
		if v == nil {
			v = &mavenVersioning{}
		}
		cached := map[string]store.Artifact{}
		known := map[string]mavenVersionCandidate{}
		knownSnapshots := map[string]mavenSnapshotVersion{}
		for _, a := range member.Artifacts {
			cached[a.Path] = a
		}
		if md.Artifact != "" && md.Version == "" {
			for _, a := range member.Artifacts {
				rel := strings.TrimPrefix(a.Path, dir+"/")
				parts := strings.Split(rel, "/")
				if len(parts) != 2 || !mavenComponent(parts[0]) {
					continue
				}
				version := parts[0]
				pom := parts[1] == md.Artifact+"-"+version+".pom"
				if strings.HasSuffix(version, "-SNAPSHOT") {
					entry, ok := referenceSnapshotFilename(md.Artifact, version, a)
					pom = ok && entry.Extension == "pom" && entry.Classifier == ""
					if pom {
						if old, seen := knownSnapshots[version]; seen && !mavenSnapshotNewer(entry, old) {
							continue
						}
						knownSnapshots[version] = entry
					}
				}
				if !pom {
					continue
				}
				when := a.Created.UTC().Format("20060102150405.000000000")
				old, exists := known[version]
				if !exists || when >= old.updated || strings.HasSuffix(version, "-SNAPSHOT") {
					known[version] = mavenVersionCandidate{mavenBlocked(a, review), when}
				}
			}
			candidates := append([]string{}, v.Versions...)
			if member.Repository.Mode == "proxy" {
				for _, hint := range []string{v.Latest, v.Release} {
					if hint != "" {
						candidates = append(candidates, hint)
					}
				}
			}
			if member.Repository.Mode == "hosted" {
				for version := range known {
					candidates = append(candidates, version)
				}
			}
			sort.Strings(candidates)
			for _, version := range candidates {
				if !mavenSourceAllowed(view.Group, member.Repository.Name, dir+"/"+version+"/") {
					continue
				}
				if _, seen := versions[version]; seen {
					continue
				}
				entry, exists := known[version]
				if !exists && member.Repository.Mode == "hosted" {
					continue
				}
				if !exists {
					entry = mavenVersionCandidate{blocked: member.Repository.Mode == "hosted" || review, updated: v.Updated}
				}
				// A known denied ordinary JAR/POM must not be replaced by a
				// lower-priority source just because catalog XML advertises it.
				for _, extension := range []string{"pom", "jar"} {
					if a, ok := cached[dir+"/"+version+"/"+md.Artifact+"-"+version+"."+extension]; ok && mavenBlocked(a, review) {
						entry.blocked = true
					}
				}
				if member.Repository.Mode == "proxy" {
					entry.updated = v.Updated
				}
				versions[version] = entry
				if entry.blocked {
					continue
				}
				when := entry.updated
				if when == "" {
					when = v.Updated
				}
				if latest == "" || when > latestTime || when == latestTime && latestDocument == documentIndex && version == v.Latest {
					latest, latestTime, latestDocument = version, when, documentIndex
				}
				if !strings.HasSuffix(version, "-SNAPSHOT") && (release == "" || when > releaseTime || when == releaseTime && releaseDocument == documentIndex && version == v.Release) {
					release, releaseTime, releaseDocument = version, when, documentIndex
				}
				if when > updated {
					updated = when
				}
			}
		}
		if md.Version != "" {
			entries := append([]mavenSnapshotVersion{}, v.Snapshots...)
			if member.Repository.Mode == "hosted" {
				for _, a := range member.Artifacts {
					if path.Dir(a.Path) != dir {
						continue
					}
					entry, ok := referenceSnapshotFilename(md.Artifact, md.Version, a)
					if ok {
						entries = append(entries, entry)
					}
				}
			}
			// Legacy metadata may contain only timestamp/buildNumber.
			if len(entries) == 0 && v.Snapshot != nil && v.Snapshot.Timestamp != "" {
				for _, extension := range []string{"pom", "jar"} {
					entries = append(entries, mavenSnapshotVersion{Extension: extension, Value: strings.TrimSuffix(md.Version, "SNAPSHOT") + v.Snapshot.Timestamp + "-" + strconv.Itoa(v.Snapshot.Build), Updated: v.Updated})
				}
			}
			for _, entry := range entries {
				if entry.Updated == "" {
					entry.Updated = v.Updated
				}
				file := mavenSnapshotPath(dir, md.Artifact, entry)
				if !mavenSourceAllowed(view.Group, member.Repository.Name, file) {
					continue
				}
				a, exists := cached[file]
				if !exists && member.Repository.Mode == "hosted" {
					continue
				}
				blocked := (!exists && (member.Repository.Mode == "hosted" || review)) || (exists && mavenBlocked(a, review))
				// The ordinary raw group path owns a duplicate filename in its
				// first source, even when its current digest is denied.
				if first, ok := firstReferences[file]; ok && first.source != member.Repository.Name {
					for _, source := range view.Members {
						if source.Repository.Name == first.source {
							blocked = blocked || mavenBlocked(first.artifact, view.Group.RequireReview || source.Repository.RequireReview)
							break
						}
					}
				}
				key := entry.Extension + "/" + entry.Classifier
				old, seen := snapshots[key]
				if !seen || mavenSnapshotNewer(entry, old.value) {
					snapshots[key] = mavenSnapshotCandidate{entry, blocked}
				}
			}
		}
		type pluginState struct{ found, allowed bool }
		pluginStates := map[string]pluginState{}
		for _, a := range member.Artifacts {
			rel := strings.TrimPrefix(a.Path, dir+"/")
			parts := strings.Split(rel, "/")
			if len(parts) != 3 || !strings.HasSuffix(parts[2], ".pom") {
				continue
			}
			state := pluginStates[parts[0]]
			state.found = true
			state.allowed = state.allowed || !mavenBlocked(a, review)
			pluginStates[parts[0]] = state
		}
		for _, plugin := range md.Plugins {
			if !mavenSourceAllowed(view.Group, member.Repository.Name, dir+"/"+plugin.Artifact+"/") {
				continue
			}
			if _, seen := plugins[plugin.Prefix]; seen {
				continue
			}
			state := pluginStates[plugin.Artifact]
			blocked := (!state.found && (review || member.Repository.Mode == "hosted")) || (state.found && !state.allowed)
			if blocked {
				plugins[plugin.Prefix] = nil
			} else {
				copy := plugin
				plugins[plugin.Prefix] = &copy
			}
		}
	}
	if len(versions)+len(snapshots)+len(plugins) > limit {
		return nil, store.ErrMetadataLimit
	}
	if out.Artifact != "" {
		if len(updated) > 14 {
			updated = updated[:14]
		}
		out.Versioning = &mavenVersioning{Latest: latest, Release: release, Updated: updated}
		for version, candidate := range versions {
			if !candidate.blocked {
				out.Versioning.Versions = append(out.Versioning.Versions, version)
			}
		}
		sort.Strings(out.Versioning.Versions)
		var newest mavenSnapshotVersion
		for _, candidate := range snapshots {
			if !candidate.blocked {
				out.Versioning.Snapshots = append(out.Versioning.Snapshots, candidate.value)
				if newest.Value == "" || mavenSnapshotNewer(candidate.value, newest) {
					newest = candidate.value
				}
			}
		}
		sort.Slice(out.Versioning.Snapshots, func(a, b int) bool {
			x, y := out.Versioning.Snapshots[a], out.Versioning.Snapshots[b]
			return x.Extension+"/"+x.Classifier < y.Extension+"/"+y.Classifier
		})
		if newest.Value != "" {
			out.Versioning.Updated = newest.Updated
			if newest.Value == out.Version {
				out.Versioning.Snapshot = &mavenSnapshot{Local: true}
			}
			tail := strings.TrimPrefix(newest.Value, strings.TrimSuffix(out.Version, "SNAPSHOT"))
			if len(tail) > 16 && tail[15] == '-' {
				n, _ := strconv.Atoi(tail[16:])
				out.Versioning.Snapshot = &mavenSnapshot{Timestamp: tail[:15], Build: n}
			}
		}
	}
	for _, plugin := range plugins {
		if plugin != nil {
			out.Plugins = append(out.Plugins, *plugin)
		}
	}
	sort.Slice(out.Plugins, func(a, b int) bool { return out.Plugins[a].Prefix < out.Plugins[b].Prefix })
	if (out.Versioning == nil || len(out.Versioning.Versions)+len(out.Versioning.Snapshots) == 0) && len(out.Plugins) == 0 {
		return nil, store.ErrNotFound
	}
	data, e := xml.Marshal(out)
	if e != nil {
		return nil, e
	}
	data = append([]byte(xml.Header), data...)
	if int64(len(data)) > maxBytes {
		return nil, store.ErrMetadataLimit
	}
	return data, nil
}

func (s *Server) mavenMetadataBytes(ctx context.Context, i store.Identity, repo store.Repository, p string, force bool) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		data, e := s.mavenMetadataAttempt(ctx, i, repo, p, force && attempt == 0)
		if !errors.Is(e, store.ErrConflict) {
			return data, e
		}
	}
	return nil, errMavenViewChanged
}

func (s *Server) mavenMetadataAttempt(ctx context.Context, i store.Identity, repo store.Repository, p string, force bool) ([]byte, error) {
	repositories, e := s.DB.NativeRepositories(ctx, i, repo.Name, path.Dir(p), "maven")
	if e != nil {
		return nil, e
	}
	for _, source := range repositories {
		if source.Mode != "proxy" {
			continue
		}
		_, e = s.resolveProxy(ctx, i, source, p, force)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
	}
	view, e := s.DB.MavenMetadataView(ctx, i, repo.Name, p, s.NativeVersionLimit, s.NativeMetadataBytes)
	if e != nil {
		return nil, e
	}
	documents := []mavenDocument{}
	remaining := s.NativeMetadataBytes
	records := s.NativeVersionLimit
	for _, member := range view.Members {
		var md mavenMetadata
		if member.Catalog != nil {
			a := member.Catalog
			if a.Size > remaining {
				return nil, store.ErrMetadataLimit
			}
			file, e := s.Blobs.OpenVerified(ctx, i.Tenant, a.Digest, a.Size)
			if e != nil {
				return nil, e
			}
			data, e := io.ReadAll(io.LimitReader(file, remaining+1))
			file.Close()
			if e != nil {
				return nil, e
			}
			remaining -= int64(len(data))
			if remaining < 0 {
				return nil, store.ErrMetadataLimit
			}
			md, e = parseMavenMetadata(data, p, records, s.NativeMetadataBytes)
			if e != nil {
				return nil, e
			}
		} else if member.Repository.Mode == "hosted" {
			md.Artifact = path.Base(path.Dir(p))
			md.Group = strings.ReplaceAll(path.Dir(path.Dir(p)), "/", ".")
			if strings.HasSuffix(md.Artifact, "-SNAPSHOT") {
				md.Version = md.Artifact
				md.Artifact = path.Base(path.Dir(path.Dir(p)))
				md.Group = strings.ReplaceAll(path.Dir(path.Dir(path.Dir(p))), "/", ".")
			}
		} else {
			continue
		}
		if md.Versioning != nil {
			records -= len(md.Versioning.Versions) + len(md.Versioning.Snapshots)
		}
		records -= len(md.Plugins)
		if records < 0 {
			return nil, store.ErrMetadataLimit
		}
		documents = append(documents, mavenDocument{md, member})
	}
	data, e := renderMavenMetadata(view, documents, p, s.NativeVersionLimit, s.NativeMetadataBytes)
	if e != nil {
		return nil, e
	}
	current, e := s.DB.MavenMetadataView(ctx, i, repo.Name, p, s.NativeVersionLimit, s.NativeMetadataBytes)
	if e != nil {
		return nil, e
	}
	if !reflect.DeepEqual(view, current) {
		return nil, store.ErrConflict
	}
	return data, nil
}

func (s *Server) serveMavenMetadata(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p, algorithm string) {
	data, e := s.mavenMetadataBytes(r.Context(), i, repo, p, forceRefresh(r))
	if e != nil {
		respondErr(w, e)
		return
	}
	if algorithm != "" {
		hash := crypt.CompatibilityHash(algorithm)
		_, _ = hash.Write(data)
		data = []byte(hex.EncodeToString(hash.Sum(nil)))
		w.Header().Set("Content-Type", "text/plain")
	} else {
		w.Header().Set("Content-Type", "application/xml")
	}
	digest := crypt.Digest(data)
	w.Header().Set("ETag", `"sha256:`+digest+`"`)
	w.Header().Set("X-Checksum-Sha256", digest)
	w.Header().Set("X-Cratectl-Repository", repo.Name)
	http.ServeContent(w, r, path.Base(p), time.Time{}, bytes.NewReader(data))
}
