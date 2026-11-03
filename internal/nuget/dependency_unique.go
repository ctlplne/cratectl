// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"
)

func dependencyUpper(r rune, pairs []dependencyUpperPair) rune {
	lo, hi := 0, len(pairs)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if pairs[mid].from < r {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(pairs) && pairs[lo].from == r {
		return pairs[lo].to
	}
	return r
}

func dependencyInvariant(r rune) rune {
	if r == 0x0131 {
		return r
	} // .NET invariant casing keeps dotless i.
	return dependencyUpper(r, dependencyInvariantUpper[:])
}

func dependencyOrdinal(r rune) rune {
	if r == 0x0131 || r == 0x017f {
		return r
	} // Ordinal casing also keeps long s.
	if r > 0xffff {
		return dependencyUpper(r, dependencySupplementaryUpper[:])
	}
	return dependencyInvariant(r)
}

// DependencyIDKey is a comparison key, separate from the flat-container IDKey.
// For example Kelvin sign and ASCII K share a flat key but differ ordinally.
func DependencyIDKey(value string) (string, error) {
	if _, e := IDKey(value); e != nil {
		return "", e
	}
	return strings.Map(dependencyOrdinal, value), nil
}

func dependencyFlags(value string) string {
	if value == "" {
		return ""
	}
	// The SDK trims/splits flags, removes ordinal duplicates and retains the
	// first spelling. Preserve a second invariant key for its hash semantics.
	seen := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		if part == "" {
			continue
		}
		part = strings.TrimSpace(part)
		ordinal := strings.Map(dependencyOrdinal, part)
		if _, ok := seen[ordinal]; !ok {
			seen[ordinal] = strings.Map(dependencyInvariant, part)
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key)
		out.WriteByte(0)
		out.WriteString(seen[key])
		out.WriteByte(0)
	}
	return out.String()
}

// UniqueNuspecDependencies projects each group's SDK-style dependency set while
// retaining the first original declaration. It never merges version-coordinate
// ordering ties or framework groups, nor edits the retained raw manifest.
func UniqueNuspecDependencies(ctx context.Context, input NuspecDependencies) (NuspecDependencies, error) {
	if len(input.Groups) > MaxNuspecDependencyGroups {
		return NuspecDependencies{}, ErrNuspecDependencies
	}
	result := NuspecDependencies{Identity: input.Identity, Groups: make([]NuspecDependencyGroup, 0, len(input.Groups))}
	type key struct {
		id, min, max, include, exclude string
		incMin, incMax                 bool
	}
	items := 0
	textBytes := 0
	for _, group := range input.Groups {
		textBytes += len(group.TargetFramework)
		if len(group.TargetFramework) > MaxNuspecDependencyFieldBytes || textBytes > MaxNuspecBytes || !utf8.ValidString(group.TargetFramework) {
			return NuspecDependencies{}, ErrNuspecDependencies
		}
		out := NuspecDependencyGroup{TargetFramework: group.TargetFramework, Dependencies: []NuspecDependency{}}
		seen := map[key]bool{}
		for _, dep := range group.Dependencies {
			if e := ctx.Err(); e != nil {
				return NuspecDependencies{}, e
			}
			items++
			textBytes += len(dep.ID) + len(dep.RawRange) + len(dep.Include) + len(dep.Exclude)
			if textBytes > MaxNuspecBytes || !utf8.ValidString(dep.Include) || !utf8.ValidString(dep.Exclude) {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			if items > MaxNuspecDependencies || len(dep.Include) > MaxNuspecDependencyFieldBytes || len(dep.Exclude) > MaxNuspecDependencyFieldBytes {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			id, e := DependencyIDKey(dep.ID)
			if e != nil {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			raw := dep.RawRange
			if raw == "" {
				raw = "(, )"
			}
			r, e := ParseVersionRange(raw)
			if e != nil {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			info := r.Info()
			dep.Range = info
			k := key{id, info.Min, info.Max, dependencyFlags(dep.Include), dependencyFlags(dep.Exclude), info.IncludeMin, info.IncludeMax}
			if seen[k] {
				continue
			}
			seen[k] = true
			out.Dependencies = append(out.Dependencies, dep)
		}
		result.Groups = append(result.Groups, out)
	}
	if e := ctx.Err(); e != nil {
		return NuspecDependencies{}, e
	}
	return result, nil
}
