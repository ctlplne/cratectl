// SPDX-License-Identifier: BUSL-1.1
package composer

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

const CatalogBytes = 8 << 20

var ErrCatalog = errors.New("invalid or ambiguous Composer v2 package metadata")

var sha1Hex = regexp.MustCompile(`^[a-f0-9]{40}$`)
var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

type RemoteDistribution struct {
	Package Package `json:"package"`
	URL     string  `json:"url"`
	SHA1    string  `json:"sha1,omitempty"`
	SHA256  string  `json:"sha256,omitempty"`
}

func (r RemoteDistribution) ValidFor(coordinate Coordinate) bool {
	u, err := url.Parse(r.URL)
	return r.Package.ValidFor(coordinate) && r.Package.Version == coordinate.Version && r.Package.Type == "library" &&
		len(r.URL) <= 2048 && err == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http") &&
		u.User == nil && u.Path != "" && !u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(r.URL, "#") &&
		(r.SHA1 == "" || sha1Hex.MatchString(r.SHA1)) && (r.SHA256 == "" || sha256Hex.MatchString(r.SHA256)) &&
		(r.SHA1 != "" || r.SHA256 != "")
}

func (r RemoteDistribution) Coordinate() Coordinate {
	return Coordinate{Name: r.Package.Name, Version: r.Package.Version}
}

type remoteVersion struct {
	Package
	Normalized string `json:"version_normalized"`
	Dist       struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		SHA1   string `json:"shasum"`
		SHA256 string `json:"sha256"`
	} `json:"dist"`
}

// ParseCatalog reads exactly one package's Composer v2 rows. For delta
// metadata, a row inherits unchanged top-level fields from the previous row
// and an explicit __unset value removes the field. Project only the fields
// used for ZIP-library discovery, with an independent expanded byte budget.
func ParseCatalog(ctx context.Context, data []byte, name string, development bool, limit int, budget int64) ([]RemoteDistribution, error) {
	if !ValidName(name) || limit < 1 || limit > 10000 || budget < 1 || len(data) > CatalogBytes || int64(len(data)) > budget {
		return nil, ErrCatalog
	}
	var root struct {
		Packages map[string]jsontext.Value `json:"packages"`
		Minified string                    `json:"minified"`
	}
	if json.Unmarshal(data, &root) != nil || len(root.Packages) != 1 || (root.Minified != "" && root.Minified != "composer/2.0") {
		return nil, ErrCatalog
	}
	raw := root.Packages[name]
	if raw.Kind() != '[' {
		return nil, ErrCatalog
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.ReadToken(); err != nil {
		return nil, ErrCatalog
	}
	minified := root.Minified == "composer/2.0"
	current := make(map[string]jsontext.Value)
	seen := map[string]bool{}
	entries := []RemoteDistribution{}
	fields := [...]string{"name", "version", "version_normalized", "dist", "type", "description", "require", "require-dev", "conflict", "replace", "provide", "autoload"}
	for count := 0; decoder.PeekKind() != ']'; count++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, err := decoder.ReadValue()
		if err != nil || count >= limit || len(row) > ManifestBytes || row.Kind() != '{' {
			return nil, ErrCatalog
		}
		var delta map[string]jsontext.Value
		if json.Unmarshal(row, &delta) != nil {
			return nil, ErrCatalog
		}
		if !minified {
			clear(current)
		}
		for _, field := range fields {
			if value, present := delta[field]; present {
				if minified && count > 0 && string(value) == `"__unset"` {
					delete(current, field)
				} else {
					current[field] = value
				}
			}
		}
		expanded, err := json.Marshal(current)
		if err != nil || len(expanded) > ManifestBytes || int64(len(expanded)) > budget {
			return nil, ErrCatalog
		}
		budget -= int64(len(expanded))
		var version remoteVersion
		if json.Unmarshal(expanded, &version) != nil || version.Name != name || version.Version == "" {
			return nil, ErrCatalog
		}
		key := strings.ToLower(strings.TrimPrefix(version.Version, "v"))
		coordinate := Coordinate{Name: name, Version: key}
		if !validVersion(key) || (version.Type != "" && version.Type != "library") || version.Dist.Type != "zip" ||
			(version.Dist.SHA1 == "" && version.Dist.SHA256 == "") {
			continue
		}
		if coordinate.Development() != development || !version.Package.ValidFor(coordinate) ||
			(version.Normalized != "" && version.Normalized != coordinate.NormalizedVersion()) || seen[key] {
			return nil, ErrCatalog
		}
		version.Package.Version, version.Package.Type = key, "library"
		entry := RemoteDistribution{Package: version.Package, URL: version.Dist.URL, SHA1: version.Dist.SHA1, SHA256: version.Dist.SHA256}
		if !entry.ValidFor(coordinate) {
			return nil, ErrCatalog
		}
		seen[key] = true
		entries = append(entries, entry)
	}
	if _, err := decoder.ReadToken(); err != nil {
		return nil, ErrCatalog
	}
	return entries, nil
}
