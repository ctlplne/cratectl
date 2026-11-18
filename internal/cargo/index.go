// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

type Entry struct {
	Name         string              `json:"name"`
	Version      string              `json:"vers"`
	Dependencies []Dependency        `json:"deps"`
	Checksum     string              `json:"cksum"`
	Features     map[string][]string `json:"features"`
	Yanked       bool                `json:"yanked"`
	Links        string              `json:"links,omitempty"`
	RustVersion  string              `json:"rust_version,omitempty"`
	Published    string              `json:"pubtime,omitempty"`
}

type Dependency struct {
	Name            string   `json:"name"`
	Requirement     string   `json:"req"`
	Features        []string `json:"features"`
	Optional        bool     `json:"optional"`
	DefaultFeatures bool     `json:"default_features"`
	Target          string   `json:"target,omitempty"`
	Kind            string   `json:"kind"`
	Package         string   `json:"package,omitempty"`
}

var (
	rustVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})(\.(0|[1-9][0-9]{0,19})){0,2}$`)
	requirement = regexp.MustCompile(`^(?:[=><~^]|[<>]=)?[ \t]*(?:\*|x|X|(?:0|[1-9][0-9]{0,19})(?:\.(?:0|[1-9][0-9]{0,19}|\*|x|X)){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$`)
)

type dependencyTable map[string]any

type manifestDependencies struct {
	Normal      dependencyTable `toml:"dependencies"`
	Dev         dependencyTable `toml:"dev-dependencies"`
	Build       dependencyTable `toml:"build-dependencies"`
	LegacyDev   dependencyTable `toml:"dev_dependencies"`
	LegacyBuild dependencyTable `toml:"build_dependencies"`
}

func parseManifest(data []byte, c Coordinate, sparseIndex string) (Entry, error) {
	var m struct {
		Package struct {
			Name        string `toml:"name"`
			Version     string `toml:"version"`
			Links       string `toml:"links"`
			RustVersion string `toml:"rust-version"`
		} `toml:"package"`
		Features map[string][]string             `toml:"features"`
		Target   map[string]manifestDependencies `toml:"target"`
		manifestDependencies
	}
	if !utf8.Valid(data) || toml.Unmarshal(data, &m) != nil || m.Package.Name != c.Name || m.Package.Version != c.Version {
		return Entry{}, ErrInput
	}
	if !cleanText(m.Package.Links, 256) || (m.Package.RustVersion != "" && !rustVersion.MatchString(m.Package.RustVersion)) {
		return Entry{}, ErrInput
	}
	if len(m.Features) > 512 || len(m.Target) > 128 {
		return Entry{}, ErrLimit
	}
	if m.Features == nil {
		m.Features = map[string][]string{}
	}
	for name, values := range m.Features {
		if name == "" || !cleanText(name, 128) || !validFeatures(values) {
			return Entry{}, ErrInput
		}
	}
	entry := Entry{Name: c.Name, Version: c.Version, Features: m.Features, Links: m.Package.Links,
		RustVersion: m.Package.RustVersion, Dependencies: []Dependency{}}
	if err := addDependencies(&entry, m.manifestDependencies, "", sparseIndex); err != nil {
		return Entry{}, err
	}
	for _, target := range slices.Sorted(maps.Keys(m.Target)) {
		if target == "" || !cleanText(target, 512) {
			return Entry{}, ErrInput
		}
		if err := addDependencies(&entry, m.Target[target], target, sparseIndex); err != nil {
			return Entry{}, err
		}
	}
	return entry, nil
}

func addDependencies(entry *Entry, tables manifestDependencies, target, index string) error {
	if tables.LegacyDev != nil && tables.Dev != nil || tables.LegacyBuild != nil && tables.Build != nil {
		return ErrInput
	}
	for _, group := range []struct {
		kind  string
		table dependencyTable
	}{
		{"normal", tables.Normal}, {"dev", tables.Dev}, {"dev", tables.LegacyDev},
		{"build", tables.Build}, {"build", tables.LegacyBuild},
	} {
		if len(entry.Dependencies)+len(group.table) > 1024 {
			return ErrLimit
		}
		for _, name := range slices.Sorted(maps.Keys(group.table)) {
			dep, err := parseDependency(name, target, group.kind, index, group.table[name])
			if err != nil {
				return err
			}
			entry.Dependencies = append(entry.Dependencies, dep)
		}
	}
	return nil
}

func parseDependency(name, target, kind, sparseIndex string, data any) (Dependency, error) {
	if _, err := NameKey(name); err != nil {
		return Dependency{}, err
	}
	d := Dependency{Name: name, Target: target, Kind: kind, DefaultFeatures: true, Features: []string{}}
	switch value := data.(type) {
	case string:
		d.Requirement = value
	case map[string]any:
		for key, field := range value {
			var ok bool
			switch key {
			case "version":
				d.Requirement, ok = field.(string)
			case "package":
				d.Package, ok = field.(string)
				_, err := NameKey(d.Package)
				ok = ok && err == nil
			case "optional":
				d.Optional, ok = field.(bool)
			case "default-features", "default_features":
				d.DefaultFeatures, ok = field.(bool)
				if _, legacy := value["default_features"]; legacy {
					_, canonical := value["default-features"]
					ok = ok && !canonical
				}
			case "features":
				values, valid := field.([]any)
				ok = valid
				for _, item := range values {
					feature, valid := item.(string)
					if !valid {
						return Dependency{}, ErrInput
					}
					d.Features = append(d.Features, feature)
				}
			case "registry-index":
				source, valid := field.(string)
				ok = valid && sparseIndex != "" && source == sparseIndex
			}
			// Workspace and non-registry sources need their own reviewed profile.
			if !ok {
				return Dependency{}, ErrInput
			}
		}
	default:
		return Dependency{}, ErrInput
	}
	if len(d.Requirement) == 0 || len(d.Requirement) > 512 || !validFeatures(d.Features) {
		return Dependency{}, ErrInput
	}
	for part := range strings.SplitSeq(d.Requirement, ",") {
		if !requirement.MatchString(strings.TrimSpace(part)) {
			return Dependency{}, ErrInput
		}
	}
	return d, nil
}

func cleanText(value string, max int) bool {
	return len(value) <= max && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validFeatures(features []string) bool {
	if len(features) > 256 {
		return false
	}
	for _, value := range features {
		if value == "" || !cleanText(value, 256) {
			return false
		}
	}
	return true
}
