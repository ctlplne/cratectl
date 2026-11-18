// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type SparseEntry struct {
	Entry
	Format    int                 `json:"v,omitempty"`
	Features2 map[string][]string `json:"features2,omitempty"`
}

type sparseDependency struct {
	Dependency
	Registry        *string `json:"registry"`
	Optional        *bool   `json:"optional"`
	DefaultFeatures *bool   `json:"default_features"`
}

var checksum = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ParseSparseIndex validates the entire bounded newline-delimited index before
// the caller pins any version. Only dependencies on this registry are admitted.
func ParseSparseIndex(data []byte, name string, limit int) ([]SparseEntry, error) {
	if limit < 1 || limit > 10000 || len(data) > 32<<20 {
		return nil, ErrLimit
	}
	var entries []SparseEntry
	seen := map[string]bool{}
	for row := range bytes.SplitSeq(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		if len(entries) >= limit || len(row) > MaxIndexBytes {
			return nil, ErrLimit
		}
		entry, versionKey, err := parseSparseEntry(row, name)
		if err != nil {
			return nil, err
		}
		if seen[versionKey] || (len(entries) > 0 && entries[0].Name != entry.Name) {
			return nil, ErrInput
		}
		seen[versionKey] = true
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseSparseEntry(row []byte, name string) (SparseEntry, string, error) {
	var item struct {
		SparseEntry
		Dependencies []sparseDependency `json:"deps"`
		Yanked       *bool              `json:"yanked"`
	}
	if !validJSONObject(row) || json.Unmarshal(row, &item) != nil || item.Dependencies == nil || item.Yanked == nil {
		return SparseEntry{}, "", ErrInput
	}
	e := item.SparseEntry
	key, err := NameKey(e.Name)
	version, versionErr := VersionKey(e.Version)
	if err != nil || key != name || versionErr != nil || !checksum.MatchString(e.Checksum) ||
		e.Format < 0 || e.Format > 2 || (e.Format != 2 && len(e.Features2) > 0) ||
		!cleanText(e.Links, 256) || (e.RustVersion != "" && !rustVersion.MatchString(e.RustVersion)) {
		return SparseEntry{}, "", ErrInput
	}
	if e.Published != "" {
		if _, err := time.Parse(time.RFC3339Nano, e.Published); err != nil || len(e.Published) > 64 {
			return SparseEntry{}, "", ErrInput
		}
	}
	if len(item.Dependencies) > 1024 || len(e.Features)+len(e.Features2) > 512 {
		return SparseEntry{}, "", ErrLimit
	}
	if e.Features == nil {
		e.Features = map[string][]string{}
	}
	for _, values := range []map[string][]string{e.Features, e.Features2} {
		for field, features := range values {
			if field == "" || !cleanText(field, 128) || features == nil || !validFeatures(features) {
				return SparseEntry{}, "", ErrInput
			}
		}
	}
	e.Dependencies = make([]Dependency, 0, len(item.Dependencies))
	for _, upstreamDep := range item.Dependencies {
		d := upstreamDep.Dependency
		if upstreamDep.Optional == nil || upstreamDep.DefaultFeatures == nil {
			return SparseEntry{}, "", ErrInput
		}
		d.Optional, d.DefaultFeatures = *upstreamDep.Optional, *upstreamDep.DefaultFeatures
		if d.Kind == "" {
			d.Kind = "normal"
		}
		if d.Features == nil {
			d.Features = []string{}
		}
		if _, err := NameKey(d.Name); err != nil || upstreamDep.Registry != nil ||
			!validRequirement(d.Requirement) || !validFeatures(d.Features) || !cleanText(d.Target, 512) ||
			(d.Kind != "normal" && d.Kind != "build" && d.Kind != "dev") {
			return SparseEntry{}, "", ErrInput
		}
		if d.Package != "" {
			if _, err := NameKey(d.Package); err != nil {
				return SparseEntry{}, "", ErrInput
			}
		}
		e.Dependencies = append(e.Dependencies, d)
	}
	e.Description = ""
	e.Yanked = *item.Yanked
	return e, version, nil
}

func ParseDownloadTemplate(data []byte) (string, error) {
	var config struct {
		Download string `json:"dl"`
	}
	if len(data) > 16<<10 {
		return "", ErrLimit
	}
	if !validJSONObject(data) || json.Unmarshal(data, &config) != nil || config.Download == "" || len(config.Download) > 2048 {
		return "", ErrInput
	}
	return config.Download, nil
}

// DownloadURL expands Cargo's registry markers. The caller must still admit
// the resulting endpoint against the operator's configured source authorities.
func DownloadURL(template string, e SparseEntry) (string, error) {
	key, err := NameKey(e.Name)
	if err != nil || !checksum.MatchString(e.Checksum) {
		return "", ErrInput
	}
	if _, err := VersionKey(e.Version); err != nil {
		return "", err
	}
	u, err := url.Parse(template)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || strings.Contains(template, "%") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		strings.ContainsAny(u.Host, "{}") {
		return "", ErrInput
	}
	prefix := "1"
	switch len(key) {
	case 2:
		prefix = "2"
	case 3:
		prefix = "3/" + e.Name[:1]
	default:
		if len(key) >= 4 {
			prefix = e.Name[:2] + "/" + e.Name[2:4]
		}
	}
	expanded := strings.NewReplacer("{crate}", e.Name, "{version}", e.Version,
		"{prefix}", prefix, "{lowerprefix}", strings.ToLower(prefix), "{sha256-checksum}", e.Checksum).Replace(template)
	if expanded == template {
		expanded = strings.TrimSuffix(template, "/") + "/" + e.Name + "/" + e.Version + "/download"
	}
	if strings.ContainsAny(expanded, "{}") || len(expanded) > 2048 {
		return "", ErrInput
	}
	return expanded, nil
}

// MatchesArchive compares the resolution fields that can change the bytes Cargo
// selects. Index-only yank state and publication time are intentionally mutable.
func (e SparseEntry) MatchesArchive(a Entry) bool {
	if e.Name != a.Name || e.Version != a.Version || e.Links != a.Links || e.RustVersion != a.RustVersion ||
		!slices.Equal(dependencyOrder(e.Dependencies), dependencyOrder(a.Dependencies)) {
		return false
	}
	features := map[string][]string{}
	for _, entries := range []map[string][]string{e.Features, e.Features2} {
		for name, values := range entries {
			features[name] = append(features[name], values...)
		}
	}
	return maps.EqualFunc(features, a.Features, sameSet)
}

func dependencyOrder(deps []Dependency) []string {
	order := make([]string, 0, len(deps))
	for _, dep := range deps {
		terms := strings.Split(strings.Join(strings.Fields(dep.Requirement), ""), ",")
		for n, term := range terms {
			terms[n] = strings.TrimPrefix(term, "^")
		}
		slices.Sort(terms)
		dep.Requirement = strings.Join(terms, ",")
		dep.Features = sortedSet(dep.Features)
		encoded, _ := json.Marshal(dep)
		order = append(order, string(encoded))
	}
	slices.Sort(order)
	return order
}

func sameSet(a, b []string) bool { return slices.Equal(sortedSet(a), sortedSet(b)) }

func sortedSet(values []string) []string {
	result := append([]string{}, values...)
	slices.Sort(result)
	return slices.Compact(result)
}

// Typed decoding follows this walk so duplicate members cannot silently select
// different checksums or dependency graphs in other JSON readers.
func validJSONObject(data []byte) bool {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || !utf8.Valid(data) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if !uniqueJSONValue(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func uniqueJSONValue(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	value, err := d.Token()
	if err != nil {
		return false
	}
	switch value {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			field, ok := key.(string)
			if err != nil || !ok || seen[field] || ((depth == 0 || depth == 2) && strings.ToLower(field) != field) || !uniqueJSONValue(d, depth+1) {
				return false
			}
			seen[field] = true
		}
		value, err = d.Token()
		return err == nil && value == json.Delim('}')
	case json.Delim('['):
		for d.More() {
			if !uniqueJSONValue(d, depth+1) {
				return false
			}
		}
		value, err = d.Token()
		return err == nil && value == json.Delim(']')
	case json.Delim('}'), json.Delim(']'):
		return false
	default:
		return true
	}
}
