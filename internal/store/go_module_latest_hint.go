// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

const GoModuleLatestProfile = "go-module-latest-v1"
const GoModuleLatestMedia = "application/vnd.cratectl.go-module-latest"
const MaxGoModuleLatestMetadata = 4096

// An upstream latest advertisement binds its original response bytes to a
// coordinate. It is not a package publication, checksum authority or approval.
type GoModuleLatest struct {
	Profile    string `json:"go_module_latest_profile"`
	Module     string `json:"module"`
	Version    string `json:"version"`
	InfoDigest string `json:"upstream_info_sha256"`
	InfoBytes  int64  `json:"upstream_info_bytes"`
}

func GoModuleLatestPath(mod string) string {
	path := GoModuleCatalogPath(mod)
	if path == "" {
		return ""
	}
	return "go-latest/" + strings.TrimPrefix(path, "go-catalog/")
}

func NewGoModuleLatest(mod string, data []byte) (GoModuleLatest, error) {
	info, e := gomodule.ParseLatestVersionInfo(data, mod)
	if e != nil {
		return GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	return GoModuleLatest{Profile: GoModuleLatestProfile, Module: mod, Version: info.Version, InfoDigest: crypt.Digest(data), InfoBytes: int64(len(data))}, nil
}

func ValidateGoModuleLatestArtifact(a Artifact) (GoModuleLatest, error) {
	if len(a.Metadata) > MaxGoModuleLatestMetadata || !utf8.Valid(a.Metadata) {
		return GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	d := json.NewDecoder(bytes.NewReader(a.Metadata))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	var c GoModuleLatest
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || seen[name] || len(seen) >= 5 {
			return GoModuleLatest{}, ErrGoModuleUnvalidated
		}
		seen[name] = true
		switch name {
		case "go_module_latest_profile":
			e = d.Decode(&c.Profile)
		case "module":
			e = d.Decode(&c.Module)
		case "version":
			e = d.Decode(&c.Version)
		case "upstream_info_sha256":
			e = d.Decode(&c.InfoDigest)
		case "upstream_info_bytes":
			e = d.Decode(&c.InfoBytes)
		default:
			return GoModuleLatest{}, ErrGoModuleUnvalidated
		}
		if e != nil {
			return GoModuleLatest{}, ErrGoModuleUnvalidated
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != 5 {
		return GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	if _, e = d.Token(); e != io.EOF {
		return GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	if _, e = gomodule.Canonical(c.Module, c.Version); e != nil || c.Profile != GoModuleLatestProfile || !uploadDigest.MatchString(c.InfoDigest) || c.InfoBytes < 1 || c.InfoBytes > gomodule.MaxVersionInfo || a.Path != GoModuleLatestPath(c.Module) || a.MediaType != GoModuleLatestMedia || a.Digest != c.InfoDigest || a.Size != c.InfoBytes {
		return GoModuleLatest{}, ErrGoModuleUnvalidated
	}
	return c, nil
}

func validateGoModuleLatestRetrieval(repo Repository, lease Retrieval, result RetrievalResult) error {
	if repo.Format != "go" || repo.Mode != "proxy" || lease.Repository != repo.Name || result.Status != 200 || result.Failure != "" || result.GoLatest == nil || result.Object == nil || result.GoCatalog != nil || result.GoModule != nil || result.OCI != nil || result.NativeCatalog != nil || result.NPMCatalog != nil || len(result.NPMSources) != 0 {
		return ErrGoModuleUnvalidated
	}
	a := Artifact{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
	c, e := ValidateGoModuleLatestArtifact(a)
	if e != nil || c != *result.GoLatest {
		return ErrGoModuleUnvalidated
	}
	canonical, e := json.Marshal(result.GoLatest)
	if e != nil || !bytes.Equal(canonical, result.Metadata) || result.FreshSeconds < 0 || result.FreshSeconds > 86400 || result.StaleSeconds < 0 || result.StaleSeconds > 604800 || result.ETag != "" || result.Modified != "" {
		return ErrGoModuleUnvalidated
	}
	return nil
}
