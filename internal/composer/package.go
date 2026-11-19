// SPDX-License-Identifier: BUSL-1.1
package composer

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"path"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"ctlplne.dev/cratectl/internal/ziparchive"
)

const ManifestBytes = 128 << 10
const UploadBytes = 64 << 20

var ErrPackage = errors.New("invalid or unsupported Composer library distribution")

var name = regexp.MustCompile(`^[a-z0-9]+([_.-][a-z0-9]+)*/[a-z0-9]+([_.-][a-z0-9]+)*$`)
var stableVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
var prerelease = regexp.MustCompile(`^(alpha|beta|rc)(0|[1-9][0-9]{0,8})$`)
var developmentVersion = regexp.MustCompile(`^dev-[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)
var platform = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

func ValidName(value string) bool { return len(value) <= 214 && name.MatchString(value) }

type Coordinate struct {
	Name    string
	Version string
}

func (c Coordinate) Path() string { return "dist/" + c.Name + "/" + c.Version + ".zip" }

func (c Coordinate) Development() bool { return developmentVersion.MatchString(c.Version) }

// NormalizedVersion maps a supported immutable coordinate to Composer's
// comparison form. Named development branches keep their dev- prefix.
func (c Coordinate) NormalizedVersion() string {
	if c.Development() {
		return c.Version
	}
	base, suffix, tagged := strings.Cut(c.Version, "-")
	if !tagged {
		return base + ".0"
	}
	if n, ok := strings.CutPrefix(suffix, "rc"); ok {
		suffix = "RC" + n
	}
	return base + ".0-" + suffix
}

func validVersion(value string) bool {
	if len(value) > 36 {
		return false
	}
	if developmentVersion.MatchString(value) {
		return true
	}
	base, suffix, tagged := strings.Cut(value, "-")
	return stableVersion.MatchString(base) && (!tagged || prerelease.MatchString(suffix))
}

func ParseDistribution(value string) (Coordinate, bool) {
	if len(value) > 260 {
		return Coordinate{}, false
	}
	p, ok := strings.CutPrefix(value, "dist/")
	p, suffix := strings.CutSuffix(p, ".zip")
	index := strings.LastIndexByte(p, '/')
	if !ok || !suffix || index < 0 || !ValidName(p[:index]) || !validVersion(p[index+1:]) {
		return Coordinate{}, false
	}
	return Coordinate{Name: p[:index], Version: p[index+1:]}, true
}

// Package holds the Composer metadata consumed from the inspected archive.
// Download authority and version normalization are derived by the repository.
type Package struct {
	Name        string            `json:"name"`
	Version     string            `json:"version,omitempty"`
	Type        string            `json:"type,omitempty"`
	Description string            `json:"description,omitempty"`
	Require     map[string]string `json:"require,omitempty"`
	RequireDev  map[string]string `json:"require-dev,omitempty"`
	Conflict    map[string]string `json:"conflict,omitempty"`
	Replace     map[string]string `json:"replace,omitempty"`
	Provide     map[string]string `json:"provide,omitempty"`
	Autoload    *Autoload         `json:"autoload,omitempty"`
}

func (p Package) SameInstallation(other Package) bool {
	return p.Name == other.Name && p.Version == other.Version && p.Type == other.Type &&
		maps.Equal(p.Require, other.Require) && maps.Equal(p.RequireDev, other.RequireDev) &&
		maps.Equal(p.Conflict, other.Conflict) && maps.Equal(p.Replace, other.Replace) &&
		maps.Equal(p.Provide, other.Provide) && reflect.DeepEqual(p.Autoload, other.Autoload)
}

type Autoload struct {
	PSR4     map[string]PathList `json:"psr-4,omitempty"`
	PSR0     map[string]PathList `json:"psr-0,omitempty"`
	Classmap []string            `json:"classmap,omitempty"`
	Exclude  []string            `json:"exclude-from-classmap,omitempty"`
	Files    []string            `json:"files,omitempty"`
}

// A Composer namespace may use a single string or an ordered list of paths.
type PathList []string

func (paths *PathList) UnmarshalJSON(raw []byte) error {
	if len(raw) > 0 && raw[0] == '"' {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return err
		}
		*paths = []string{single}
		return nil
	}
	return json.Unmarshal(raw, (*[]string)(paths))
}

func (p Package) ValidFor(c Coordinate) bool {
	if !ValidName(c.Name) || !validVersion(c.Version) || p.Name != c.Name || !packageVersionMatches(p.Version, c) ||
		(p.Type != "" && p.Type != "library") || !text(p.Description, 4096) {
		return false
	}
	for _, links := range [...]map[string]string{p.Require, p.RequireDev, p.Conflict, p.Replace, p.Provide} {
		if len(links) > 128 {
			return false
		}
		for target, constraint := range links {
			if (!ValidName(target) && !platform.MatchString(target)) || strings.TrimSpace(constraint) == "" || !text(constraint, 512) {
				return false
			}
		}
	}
	return p.Autoload == nil || p.Autoload.valid()
}

func packageVersionMatches(version string, c Coordinate) bool {
	if version == "" || version == c.Version {
		return true
	}
	if c.Development() {
		return false
	}
	return strings.ToLower(strings.TrimPrefix(version, "v")) == c.Version
}

func (a Autoload) valid() bool {
	for _, entries := range [...]map[string]PathList{a.PSR4, a.PSR0} {
		if len(entries) > 128 {
			return false
		}
		for namespace, paths := range entries {
			if !text(namespace, 256) || len(paths) == 0 || !relativePaths(paths, true) {
				return false
			}
		}
	}
	return relativePaths(a.Classmap, false) && relativePaths(a.Exclude, false) && relativePaths(a.Files, false)
}

func text(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

func relativePaths(paths []string, allowRoot bool) bool {
	if len(paths) > 128 {
		return false
	}
	for _, value := range paths {
		p := strings.TrimSuffix(value, "/")
		if (p == "" || p == ".") && allowRoot && (value == "" || value == "." || value == "./") {
			continue
		}
		if p == "" || p == "." || p == ".." || !text(p, 512) || strings.ContainsAny(p, "\\:") ||
			path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") {
			return false
		}
	}
	return true
}

// Inspect validates the ZIP before accepting one root composer.json. A Git-style
// wrapper directory is accepted only when every archive entry belongs to it.
func Inspect(ctx context.Context, input io.ReaderAt, size int64, c Coordinate) (Package, error) {
	limits := ziparchive.Limits{CompressedBytes: UploadBytes, ExpandedBytes: 256 << 20, DirectoryBytes: 4 << 20, Files: 10000}
	var manifest bytes.Buffer
	var manifestPath, firstRoot string
	var mixedRoots bool
	_, err := ziparchive.Inspect(ctx, input, size, limits, func(name string, directory bool, expanded int64) (io.Writer, error) {
		root, _, _ := strings.Cut(name, "/")
		if firstRoot == "" {
			firstRoot = root
		}
		mixedRoots = mixedRoots || root != firstRoot
		_, leaf, wrapped := strings.Cut(name, "/")
		if name != "composer.json" && (!wrapped || leaf != "composer.json") {
			return nil, nil
		}
		if manifestPath != "" || directory || expanded < 1 || expanded > ManifestBytes {
			return nil, ErrPackage
		}
		manifestPath = name
		return &manifest, nil
	})
	if err != nil {
		return Package{}, err
	}
	if manifestPath == "" || (manifestPath != "composer.json" && mixedRoots) {
		return Package{}, ErrPackage
	}
	var result Package
	if json.Unmarshal(manifest.Bytes(), &result) != nil || !result.ValidFor(c) {
		return Package{}, ErrPackage
	}
	if err = ctx.Err(); err != nil {
		return Package{}, err
	}
	result.Type = "library"
	result.Version = c.Version
	return result, nil
}
