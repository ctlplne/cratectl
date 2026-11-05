// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// LatestVersion chooses among an already validated bounded set, independently
// of input order: release, prerelease, then the most recent pseudo timestamp.
func LatestVersion(versions []string) string {
	release, prerelease, pseudo := "", "", ""
	var instant time.Time
	for _, v := range versions {
		if !semver.IsValid(v) {
			continue
		}
		if module.IsPseudoVersion(v) {
			t, e := module.PseudoVersionTime(v)
			if e == nil && (pseudo == "" || t.After(instant) || t.Equal(instant) && semver.Compare(v, pseudo) > 0) {
				pseudo, instant = v, t
			}
		} else if semver.Prerelease(v) == "" {
			if release == "" || semver.Compare(v, release) > 0 {
				release = v
			}
		} else if prerelease == "" || semver.Compare(v, prerelease) > 0 {
			prerelease = v
		}
	}
	if release != "" {
		return release
	}
	if prerelease != "" {
		return prerelease
	}
	return pseudo
}

// ParseVersionList validates one bounded native upstream advertisement. This
// establishes names, not permission to serve or approval of any package bytes.
// A future proxy must merge it with current bundle/policy/cache state. Never
// return a truncated valid prefix when a later entry or resource bound fails.
func ParseVersionList(data []byte, mod string, maximum int, budget int64) ([]string, error) {
	if len(mod) > MaxModulePath || module.CheckPath(mod) != nil || maximum < 1 || maximum > 10000 || budget < 1 || budget > 64<<20 || int64(len(data)) > budget || !utf8.Valid(data) {
		return nil, ErrModule
	}
	versions := []string{}
	seen := map[string]bool{}
	for lines := data; len(lines) > 0; {
		line, tail, _ := bytes.Cut(lines, []byte{'\n'})
		lines = tail
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxVersion {
			return nil, ErrModule
		}
		version := string(line)
		if strings.TrimSpace(version) != version || len(versions) >= maximum {
			return nil, ErrModule
		}
		if _, e := Canonical(mod, version); e != nil || module.IsPseudoVersion(version) || seen[version] {
			return nil, ErrModule
		}
		seen[version] = true
		versions = append(versions, version)
	}
	semver.Sort(versions)
	return versions, nil
}
