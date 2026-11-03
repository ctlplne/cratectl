// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
)

const MaxNuspecDependencyGroups = 2048
const MaxNuspecDependencies = 8192
const MaxNuspecDependencyFieldBytes = 4096

var ErrNuspecDependencies = errors.New("invalid or oversized NuGet dependency metadata")

type NuspecDependency struct {
	ID       string           `json:"id"`
	IDKey    string           `json:"id_key"`
	RawRange string           `json:"raw_range"`
	Range    VersionRangeInfo `json:"range"`
	Include  string           `json:"include"`
	Exclude  string           `json:"exclude"`
}

type NuspecDependencyGroup struct {
	// Preserve the declaration for the native framework interpreter. An
	// unsupported framework must never silently become an unrestricted group.
	TargetFramework string             `json:"target_framework"`
	Dependencies    []NuspecDependency `json:"dependencies"`
}

type NuspecDependencies struct {
	Identity NuspecIdentity          `json:"identity"`
	Groups   []NuspecDependencyGroup `json:"groups"`
}

type dependencyFrame struct {
	defaultNS string
	metadata  bool
	container bool
	group     int
}

func dependencyAttribute(element xml.StartElement, name string) string {
	for _, a := range element.Attr {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// ParseNuspecDependencies selects the SDK's case/namespace-sensitive dependency
// nodes while preserving original framework/range/asset declarations. Any group
// overrides legacy flat dependencies, including an empty group. Invalid active
// ranges are rejected rather than silently widened; absent/empty ranges mean All.
// The result grants no security authority and never resolves or runs packages.
func ParseNuspecDependencies(ctx context.Context, raw []byte) (NuspecDependencies, error) {
	identity, e := ParseNuspecIdentity(ctx, raw)
	if e != nil {
		return NuspecDependencies{}, e
	}
	_, _, decoder, e := nuspecDecoder(raw)
	if e != nil {
		return NuspecDependencies{}, e
	}
	groups := []NuspecDependencyGroup{}
	legacy := []NuspecDependency{}
	var frames []dependencyFrame
	var metadataNS string
	items, textBytes := 0, 0
	for tokens := 0; ; tokens++ {
		if e := ctx.Err(); e != nil {
			return NuspecDependencies{}, e
		}
		if tokens >= maxNuspecTokens {
			return NuspecDependencies{}, ErrNuspecDependencies
		}
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return NuspecDependencies{}, ErrNuspecDependencies
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(frames) >= maxNuspecDepth {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			frame := dependencyFrame{group: -1}
			if len(frames) > 0 {
				frame.defaultNS = frames[len(frames)-1].defaultNS
			}
			for _, a := range value.Attr {
				if a.Name.Space == "" && a.Name.Local == "xmlns" {
					frame.defaultNS = a.Value
				}
			}
			if len(frames) == 1 && value.Name.Local == "metadata" {
				frame.metadata = true
				metadataNS = frame.defaultNS
			}
			if len(frames) == 2 && frames[1].metadata && value.Name.Local == "dependencies" && value.Name.Space == metadataNS {
				frame.container = true
			}
			if len(frames) == 3 && frames[2].container && value.Name.Local == "group" && value.Name.Space == metadataNS {
				framework := dependencyAttribute(value, "targetFramework")
				if len(groups) >= MaxNuspecDependencyGroups || len(framework) > MaxNuspecDependencyFieldBytes {
					return NuspecDependencies{}, ErrNuspecDependencies
				}
				textBytes += len(framework)
				frame.group = len(groups)
				groups = append(groups, NuspecDependencyGroup{TargetFramework: framework, Dependencies: []NuspecDependency{}})
			}
			flat := len(frames) == 3 && frames[2].container
			grouped := len(frames) == 4 && frames[3].group >= 0
			if (flat || grouped) && value.Name.Local == "dependency" && value.Name.Space == metadataNS {
				if items >= MaxNuspecDependencies {
					return NuspecDependencies{}, ErrNuspecDependencies
				}
				items++
				dep := NuspecDependency{ID: dependencyAttribute(value, "id"), RawRange: dependencyAttribute(value, "version"), Include: dependencyAttribute(value, "include"), Exclude: dependencyAttribute(value, "exclude")}
				for _, field := range []string{dep.ID, dep.RawRange, dep.Include, dep.Exclude} {
					if len(field) > MaxNuspecDependencyFieldBytes {
						return NuspecDependencies{}, ErrNuspecDependencies
					}
					textBytes += len(field)
				}
				if flat {
					legacy = append(legacy, dep)
				} else {
					index := frames[3].group
					groups[index].Dependencies = append(groups[index].Dependencies, dep)
				}
			}
			if textBytes > MaxNuspecBytes {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			frames = append(frames, frame)
		case xml.EndElement:
			frames = frames[:len(frames)-1]
		}
	}
	if len(groups) == 0 && len(legacy) > 0 {
		groups = append(groups, NuspecDependencyGroup{Dependencies: legacy})
	}
	for index := range groups {
		for item := range groups[index].Dependencies {
			if e := ctx.Err(); e != nil {
				return NuspecDependencies{}, e
			}
			dep := &groups[index].Dependencies[item]
			dep.IDKey, e = IDKey(dep.ID)
			if e != nil {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			declared := dep.RawRange
			if declared == "" {
				declared = "(, )"
			}
			allowed, e := ParseVersionRange(declared)
			if e != nil {
				return NuspecDependencies{}, ErrNuspecDependencies
			}
			dep.Range = allowed.Info()
		}
	}
	if e := ctx.Err(); e != nil {
		return NuspecDependencies{}, e
	}
	return NuspecDependencies{Identity: identity, Groups: groups}, nil
}
