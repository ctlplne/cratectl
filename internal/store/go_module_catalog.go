// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const GoModuleCatalogProfile = "go-module-catalog-v1"
const GoModuleCatalogMedia = "application/vnd.cratectl.go-module-list"
const MaxGoModuleCatalog = 4 << 20

// This is a source advertisement, never package approval. Raw list bytes remain
// a separately staged immutable object; these names are derived bounded data.
type GoModuleCatalog struct {
	Profile    string   `json:"go_module_catalog_profile"`
	Module     string   `json:"module"`
	Versions   []string `json:"versions"`
	ListDigest string   `json:"upstream_list_sha256"`
	ListBytes  int64    `json:"upstream_list_bytes"`
}

func GoModuleCatalogPath(mod string) string {
	if len(mod) > gomodule.MaxModulePath {
		return ""
	}
	escaped, e := module.EscapePath(mod)
	if e != nil {
		return ""
	}
	return "go-catalog/" + escaped
}

func NewGoModuleCatalog(mod string, data []byte, maximum int, budget int64) (GoModuleCatalog, error) {
	if budget < 1 || budget > MaxGoModuleCatalog {
		return GoModuleCatalog{}, ErrMetadataLimit
	}
	versions, e := gomodule.ParseVersionList(data, mod, maximum, budget)
	if e != nil {
		return GoModuleCatalog{}, e
	}
	return GoModuleCatalog{Profile: GoModuleCatalogProfile, Module: mod, Versions: versions, ListDigest: crypt.Digest(data), ListBytes: int64(len(data))}, nil
}

func (c GoModuleCatalog) validate() error {
	if c.Profile != GoModuleCatalogProfile || GoModuleCatalogPath(c.Module) == "" || c.Versions == nil || len(c.Versions) > 10000 || !uploadDigest.MatchString(c.ListDigest) || c.ListBytes < 0 || c.ListBytes > MaxGoModuleCatalog {
		return ErrGoModuleUnvalidated
	}
	for n, v := range c.Versions {
		if _, e := gomodule.Canonical(c.Module, v); e != nil || module.IsPseudoVersion(v) || n > 0 && semver.Compare(c.Versions[n-1], v) >= 0 {
			return ErrGoModuleUnvalidated
		}
	}
	return nil
}

func ValidateGoModuleCatalogArtifact(a Artifact) (GoModuleCatalog, error) {
	c, e := decodeGoModuleCatalog(a.Metadata)
	if e != nil || c.validate() != nil || a.Path != GoModuleCatalogPath(c.Module) || a.MediaType != GoModuleCatalogMedia || a.Digest != c.ListDigest || a.Size != c.ListBytes {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	return c, nil
}

// Count array entries before allocating the next value. A byte cap alone still
// permits hundreds of thousands of empty strings to amplify json.Unmarshal's
// slice allocations. These internal versioned fields are exact and unique.
func decodeGoModuleCatalog(data []byte) (GoModuleCatalog, error) {
	if len(data) > MaxGoModuleCatalog || !utf8.Valid(data) {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	d := json.NewDecoder(bytes.NewReader(data))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	var c GoModuleCatalog
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || seen[name] || len(seen) >= 5 {
			return GoModuleCatalog{}, ErrGoModuleUnvalidated
		}
		seen[name] = true
		switch name {
		case "go_module_catalog_profile":
			if d.Decode(&c.Profile) != nil || c.Profile != GoModuleCatalogProfile {
				return GoModuleCatalog{}, ErrGoModuleUnvalidated
			}
		case "module":
			if d.Decode(&c.Module) != nil || GoModuleCatalogPath(c.Module) == "" {
				return GoModuleCatalog{}, ErrGoModuleUnvalidated
			}
		case "upstream_list_sha256":
			if d.Decode(&c.ListDigest) != nil || !uploadDigest.MatchString(c.ListDigest) {
				return GoModuleCatalog{}, ErrGoModuleUnvalidated
			}
		case "upstream_list_bytes":
			if d.Decode(&c.ListBytes) != nil || c.ListBytes < 0 || c.ListBytes > MaxGoModuleCatalog {
				return GoModuleCatalog{}, ErrGoModuleUnvalidated
			}
		case "versions":
			start, e := d.Token()
			if e != nil || start != json.Delim('[') {
				return GoModuleCatalog{}, ErrGoModuleUnvalidated
			}
			c.Versions = []string{}
			for d.More() {
				if len(c.Versions) >= 10000 {
					return GoModuleCatalog{}, ErrGoModuleUnvalidated
				}
				var v string
				if d.Decode(&v) != nil || len(v) > gomodule.MaxVersion || !semver.IsValid(v) || module.CanonicalVersion(v) != v || module.IsPseudoVersion(v) || len(c.Versions) > 0 && semver.Compare(c.Versions[len(c.Versions)-1], v) >= 0 {
					return GoModuleCatalog{}, ErrGoModuleUnvalidated
				}
				c.Versions = append(c.Versions, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return GoModuleCatalog{}, ErrGoModuleUnvalidated
			}
		default:
			return GoModuleCatalog{}, ErrGoModuleUnvalidated
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != 5 {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	if _, e = d.Token(); e != io.EOF {
		return GoModuleCatalog{}, ErrGoModuleUnvalidated
	}
	return c, nil
}

func validateGoModuleCatalogRetrieval(repo Repository, lease Retrieval, result RetrievalResult) error {
	if repo.Format != "go" || repo.Mode != "proxy" || lease.Repository != repo.Name || result.Status != 200 || result.Failure != "" || result.GoCatalog == nil || result.GoLatest != nil || result.Object == nil || result.GoModule != nil || result.OCI != nil || result.NativeCatalog != nil || result.NPMCatalog != nil || len(result.NPMSources) != 0 {
		return ErrGoModuleUnvalidated
	}
	a := Artifact{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
	c, e := ValidateGoModuleCatalogArtifact(a)
	if e != nil || c.Module != result.GoCatalog.Module || !slices.Equal(c.Versions, result.GoCatalog.Versions) {
		return ErrGoModuleUnvalidated
	}
	canonical, e := json.Marshal(result.GoCatalog)
	if e != nil || !bytes.Equal(canonical, result.Metadata) {
		return ErrGoModuleUnvalidated
	}
	if result.FreshSeconds < 0 || result.FreshSeconds > 86400 || result.StaleSeconds < 0 || result.StaleSeconds > 604800 || result.ETag != "" || result.Modified != "" {
		// Initial profile uses full-body refresh. Independent catalog validators
		// and bare 304 are not admitted until current-cache revalidation exists.
		return ErrGoModuleUnvalidated
	}
	return nil
}
