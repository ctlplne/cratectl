// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"errors"
	"strings"
)

const MaxVersionRangeBytes = 4096

var ErrVersionRange = errors.New("invalid or oversized NuGet dependency range")

// VersionRange separates interval membership from floating preference. A floating
// prefix is not an implicit upper bound. Fields stay private so a parsed range
// cannot accidentally be widened by changing one of its projected values.
type VersionRange struct {
	minimum, maximum       orderedVersion
	hasMinimum, hasMaximum bool
	includeMin, includeMax bool
	float                  *versionFloat
	valid                  bool
}

type versionFloat struct {
	behavior, prefix string
}

type VersionRangeInfo struct {
	Normalized    string `json:"normalized"`
	Min           string `json:"min"`
	Max           string `json:"max"`
	IncludeMin    bool   `json:"include_min"`
	IncludeMax    bool   `json:"include_max"`
	Floating      bool   `json:"floating"`
	FloatBehavior string `json:"float_behavior"`
	FloatString   string `json:"float_string"`
}

// ParseVersionRange reads bounded intervals, exact/minimum versions and the
// SDK's floating forms. Invalid input produces no partially usable range.
// Normalized projections use the same lowercase version-key profile as feeds;
// callers retain the original declared text separately when they need it.
func ParseVersionRange(raw string) (VersionRange, error) {
	bad := func() (VersionRange, error) { return VersionRange{}, ErrVersionRange }
	if raw == "" || len(raw) > MaxVersionRangeBytes {
		return bad()
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return bad()
	}
	r := VersionRange{includeMin: true}
	minimum, maximum := value, ""
	if value[0] == '[' || value[0] == '(' {
		if len(value) < 2 || value[len(value)-1] != ']' && value[len(value)-1] != ')' {
			return bad()
		}
		r.includeMin, r.includeMax = value[0] == '[', value[len(value)-1] == ']'
		parts := strings.Split(value[1:len(value)-1], ",")
		if len(parts) > 2 || len(parts) == 1 && (!r.includeMin || !r.includeMax) || parts[0] == "" && (len(parts) == 1 || parts[1] == "") {
			return bad()
		}
		minimum, maximum = parts[0], parts[0]
		if len(parts) == 2 {
			maximum = parts[1]
		}
	}
	var e error
	if strings.TrimSpace(minimum) != "" {
		if strings.Contains(minimum, "*") {
			r.minimum, r.float, e = parseVersionFloat(minimum)
		} else {
			r.minimum, e = orderVersion(minimum)
		}
		if e != nil {
			return bad()
		}
		r.hasMinimum = true
	}
	if strings.TrimSpace(maximum) != "" {
		r.maximum, e = orderVersion(maximum) // Upper bounds never float.
		if e != nil {
			return bad()
		}
		r.hasMaximum = true
	}
	if r.hasMinimum && r.hasMaximum {
		order := compareOrdered(r.minimum, r.maximum)
		// An empty open interval is representable. A half-open zero-width one
		// is rejected by the SDK, including comparison ties across wire keys.
		if order > 0 || order == 0 && r.includeMin != r.includeMax {
			return bad()
		}
	}
	r.includeMin, r.includeMax = r.hasMinimum && r.includeMin, r.hasMaximum && r.includeMax
	r.valid = true
	return r, nil
}

func parseVersionFloat(raw string) (orderedVersion, *versionFloat, error) {
	f := &versionFloat{behavior: "None"}
	actual := ""
	switch raw {
	case "*":
		actual, f.behavior = "0.0.0", "Major"
	case "*-*":
		actual, f.behavior = "0.0.0-0", "AbsoluteLatest"
	default:
		if !strings.HasSuffix(raw, "*") || strings.Contains(raw, "+") {
			return orderedVersion{}, nil, ErrVersionRange
		}
		core, release, prerelease := strings.Cut(raw, "-")
		stars := strings.Count(raw, "*")
		actual = strings.TrimSuffix(raw, "*")
		if stars > 1 {
			if stars != 2 || !prerelease || !strings.HasSuffix(core, "*") || !strings.HasSuffix(release, "*") {
				return orderedVersion{}, nil, ErrVersionRange
			}
			core = strings.TrimSuffix(core, "*") + "0"
			parts := strings.Count(core, ".") + 1
			if parts < 1 || parts > 4 {
				return orderedVersion{}, nil, ErrVersionRange
			}
			f.behavior = []string{"PrereleaseMajor", "PrereleaseMinor", "PrereleasePatch", "PrereleaseRevision"}[parts-1]
			f.prefix = strings.TrimSuffix(release, "*")
			actualRelease := f.prefix
			if actualRelease == "" || strings.HasSuffix(actualRelease, ".") {
				actualRelease += "0"
			}
			actual = core + "-" + actualRelease
		} else if !prerelease {
			actual += "0"
			parts := strings.Count(actual, ".") + 1
			if parts >= 2 && parts <= 4 {
				f.behavior = []string{"Minor", "Patch", "Revision"}[parts-2]
			}
		} else {
			f.behavior = "Prerelease"
			if strings.Count(raw, "-") == 1 {
				f.prefix = strings.TrimSuffix(release, "*")
				if f.prefix == "" || strings.HasSuffix(f.prefix, ".") {
					actual += "0"
				}
			}
		}
	}
	v, e := orderVersion(actual)
	if e != nil {
		return orderedVersion{}, nil, ErrVersionRange
	}
	// Multi-dash release prefixes use the parsed release as in the SDK's
	// FloatRange constructor; an explicit empty prefix remains empty.
	if strings.Count(raw, "*") == 1 && strings.Count(raw, "-") > 1 {
		f.prefix = v.release
	}
	f.prefix = strings.ToLower(f.prefix)
	return v, f, nil
}

func (r VersionRange) Info() VersionRangeInfo {
	if !r.valid {
		return VersionRangeInfo{}
	}
	i := VersionRangeInfo{Min: r.minimum.key, Max: r.maximum.key, IncludeMin: r.includeMin, IncludeMax: r.includeMax, FloatBehavior: "None"}
	left, right, minimum := "(", ")", i.Min
	if i.IncludeMin {
		left = "["
	}
	if i.IncludeMax {
		right = "]"
	}
	if r.float != nil {
		i.FloatBehavior = r.float.behavior
		i.Floating = r.float.behavior != "None"
		i.FloatString = r.floatString()
		if i.Floating {
			minimum = i.FloatString
		}
	}
	i.Normalized = left + minimum + ", " + i.Max + right
	return i
}

func (r VersionRange) floatString() string {
	core, _, _ := strings.Cut(r.minimum.key, "-")
	parts := strings.Split(core, ".")
	switch r.float.behavior {
	case "AbsoluteLatest":
		return "*-*"
	case "Major":
		return "*"
	case "Minor":
		return parts[0] + ".*"
	case "Patch":
		return strings.Join(parts[:2], ".") + ".*"
	case "Revision":
		return strings.Join(parts[:3], ".") + ".*"
	case "Prerelease":
		return core + "-" + r.float.prefix + "*"
	case "PrereleaseMajor":
		return "*-" + r.float.prefix + "*"
	case "PrereleaseMinor":
		return parts[0] + ".*-" + r.float.prefix + "*"
	case "PrereleasePatch":
		return strings.Join(parts[:2], ".") + ".*-" + r.float.prefix + "*"
	case "PrereleaseRevision":
		return strings.Join(parts[:3], ".") + ".*-" + r.float.prefix + "*"
	}
	return r.minimum.key
}

// Satisfies tests the interval only, ignoring build metadata. Prerelease
// admission and floating best-version selection are separate client decisions.
func (r VersionRange) Satisfies(raw string) (bool, error) {
	if !r.valid {
		return false, ErrVersionRange
	}
	v, e := orderVersion(raw)
	if e != nil {
		return false, e
	}
	if r.hasMinimum {
		order := compareOrdered(v, r.minimum)
		if order < 0 || order == 0 && !r.includeMin {
			return false, nil
		}
	}
	if r.hasMaximum {
		order := compareOrdered(v, r.maximum)
		if order > 0 || order == 0 && !r.includeMax {
			return false, nil
		}
	}
	return true, nil
}

// FloatSatisfies tests the preferred floating subset, independently of interval
// bounds. Callers must also test Satisfies before selecting a candidate.
func (r VersionRange) FloatSatisfies(raw string) (bool, error) {
	if !r.valid {
		return false, ErrVersionRange
	}
	v, e := orderVersion(raw)
	if e != nil {
		return false, e
	}
	if r.float == nil || r.float.behavior == "None" {
		return false, nil
	}
	behavior, prefix := r.float.behavior, r.float.prefix
	if behavior == "AbsoluteLatest" {
		return true, nil
	}
	pre := strings.HasPrefix(behavior, "Prerelease")
	if v.release != "" && (!pre || !strings.HasPrefix(v.release, prefix)) {
		return false, nil
	}
	count := map[string]int{"Major": 0, "Minor": 1, "Patch": 2, "Revision": 3, "PrereleaseMajor": 0, "PrereleaseMinor": 1, "PrereleasePatch": 2, "PrereleaseRevision": 3, "Prerelease": 4}[behavior]
	for index := 0; index < count; index++ {
		if v.core[index] != r.minimum.core[index] {
			return false, nil
		}
	}
	return true, nil
}
