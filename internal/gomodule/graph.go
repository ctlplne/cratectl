// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"context"
	"errors"
	"go/version"
	"slices"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

var (
	ErrGraphLimit       = errors.New("Go requirement graph exceeds its work or metadata budget")
	ErrGraphUnsupported = errors.New("Go requirement graph needs an unsupported local or mutable input")
)

// GraphLimits bounds one serial, read-only metadata traversal. These are work
// limits, not entitlement limits. A caller must also bound each loader's I/O and
// deadline; cancellation is checked before every load and graph expansion.
type GraphLimits struct {
	Modules, Versions, Requirements int
	MetadataBytes                   int64
}

func DefaultGraphLimits() GraphLimits {
	return GraphLimits{Modules: 256, Versions: 1024, Requirements: 16384, MetadataBytes: 32 << 20}
}

func (l GraphLimits) valid() bool {
	return l.Modules > 0 && l.Modules <= 4096 && l.Versions > 0 && l.Versions <= 16384 &&
		l.Requirements > 0 && l.Requirements <= 65536 && l.MetadataBytes > 0 && l.MetadataBytes <= 64<<20
}

// GraphLoader must read the exact requested immutable .mod, under the caller's
// current source/permission policy. It must honor ctx and maximum before buffering
// bytes. No fallback, URL, filesystem replacement or package execution is implied.
type GraphLoader func(ctx context.Context, source Coordinate, maximum int64) ([]byte, error)

type GraphSelection struct {
	Logical Coordinate
	Source  Coordinate
}

// GraphInput retains every examined version, including lower versions which can
// influence selection without appearing in BuildList. Source is the main module's
// applicable versioned replacement; dependency-local replace/exclude are ignored.
type GraphInput struct {
	GraphSelection
	GoVersion    string
	GoModSHA256  string
	Bytes        int64
	Requirements []Coordinate
}

// RequirementGraph is a module-metadata build list, not package/platform closure
// or export admission. Modern graph pruning can leave selected modules unread.
// Package discovery, lazy expansion, source provenance, permission revalidation,
// ZIP inspection and common-snapshot binding remain separate required steps.
type RequirementGraph struct {
	MainModule, GoVersion, MainGoModSHA256 string
	MinimumGoVersion                       string
	SuggestedToolchain                     string
	Pruned                                 bool
	BuildList                              []GraphSelection
	Inputs                                 []GraphInput
	Requirements                           int
	MetadataBytes                          int64
}

// ResolveRequirements computes minimal version selection for a fixed single
// main go.mod, with Go 1.17+ pruning and legacy unpruned subgraphs. It never queries
// latest, edits go.mod, executes a toolchain, or returns a partial result. An
// excluded direct root requires a caller-reviewed updated main go.mod instead of
// silently upgrading to an unrequested version. Local replacements need a future
// explicitly supplied immutable input; server filesystem paths are never read.
func ResolveRequirements(ctx context.Context, main []byte, load GraphLoader, limits GraphLimits) (*RequirementGraph, error) {
	if ctx == nil || load == nil || !limits.valid() {
		return nil, ErrModule
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(main) == 0 || len(main) > MaxGoMod || int64(len(main)) > limits.MetadataBytes {
		return nil, ErrGraphLimit
	}
	main = slices.Clone(main)
	f, err := modfile.Parse("go.mod", main, nil)
	if err != nil || f.Module == nil || len(f.Module.Mod.Path) > MaxModulePath || module.CheckImportPath(f.Module.Mod.Path) != nil {
		return nil, ErrModule
	}
	mainGo, err := graphGoVersion(f)
	if err != nil {
		return nil, err
	}
	replacements := map[Coordinate]Coordinate{}
	for _, r := range f.Replace {
		old := Coordinate{r.Old.Path, r.Old.Version}
		if len(old.Module) > MaxModulePath || module.CheckPath(old.Module) != nil {
			return nil, ErrModule
		}
		if old.Version != "" {
			if _, err := Canonical(old.Module, old.Version); err != nil {
				return nil, ErrModule
			}
		}
		if r.New.Version == "" {
			return nil, ErrGraphUnsupported
		}
		target, err := Canonical(r.New.Path, r.New.Version)
		if err != nil {
			return nil, err
		}
		if _, exists := replacements[old]; exists {
			return nil, ErrModule
		}
		replacements[old] = target
	}
	excluded := map[Coordinate]bool{}
	for _, x := range f.Exclude {
		c, err := Canonical(x.Mod.Path, x.Mod.Version)
		if err != nil || excluded[c] {
			return nil, ErrModule
		}
		excluded[c] = true
	}
	resolveSource := func(c Coordinate) Coordinate {
		if source, ok := replacements[c]; ok {
			return source
		}
		if source, ok := replacements[Coordinate{Module: c.Module}]; ok {
			return source
		}
		return c
	}
	graph := &RequirementGraph{MainModule: f.Module.Mod.Path, GoVersion: mainGo,
		MainGoModSHA256: crypt.Digest(main), MinimumGoVersion: mainGo,
		Pruned: graphPruned(mainGo), MetadataBytes: int64(len(main))}
	if f.Toolchain != nil {
		// Retain the main module's suggestion; never resolve or execute it.
		graph.SuggestedToolchain = f.Toolchain.Name
	}
	roots, err := graphRequirements(f, limits.Requirements)
	if err != nil {
		return nil, err
	}
	for _, root := range roots {
		if excluded[root] {
			return nil, ErrGraphUnsupported
		}
	}
	graph.Requirements = len(roots)
	type visit struct {
		coordinate Coordinate
		unpruned   bool
	}
	queue := make([]visit, 0)
	enqueued := map[visit]bool{}
	selected := map[string]string{}
	inputs := map[Coordinate]int{}
	add := func(c Coordinate, traverse, unpruned bool) error {
		if c.Module == graph.MainModule || excluded[c] {
			return nil
		}
		previous, present := selected[c.Module]
		if !present && len(selected) >= limits.Modules {
			return ErrGraphLimit
		}
		if !present || semver.Compare(previous, c.Version) < 0 {
			selected[c.Module] = c.Version
		}
		v := visit{c, unpruned}
		if traverse && !enqueued[v] {
			// Each version can be traversed at most once at each pruning mode.
			if len(enqueued) >= 2*limits.Versions {
				return ErrGraphLimit
			}
			enqueued[v] = true
			queue = append(queue, v)
		}
		return nil
	}
	for _, c := range roots {
		if err := add(c, true, !graph.Pruned); err != nil {
			return nil, err
		}
	}
	for cursor := 0; cursor < len(queue); cursor++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v := queue[cursor]
		index, exists := inputs[v.coordinate]
		if !exists {
			if len(inputs) >= limits.Versions || graph.MetadataBytes >= limits.MetadataBytes {
				return nil, ErrGraphLimit
			}
			source := resolveSource(v.coordinate)
			maximum := min(int64(MaxGoMod), limits.MetadataBytes-graph.MetadataBytes)
			raw, err := load(ctx, source, maximum)
			if err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(raw) == 0 || int64(len(raw)) > maximum {
				return nil, ErrGraphLimit
			}
			raw = slices.Clone(raw)
			f, err := modfile.ParseLax("go.mod", raw, nil)
			if err != nil || f.Module == nil || f.Module.Mod.Path != v.coordinate.Module && f.Module.Mod.Path != source.Module {
				return nil, ErrModule
			}
			goVersion, err := graphGoVersion(f)
			if err != nil {
				return nil, err
			}
			if version.Compare("go"+graph.MinimumGoVersion, "go"+goVersion) < 0 {
				graph.MinimumGoVersion = goVersion
			}
			requires, err := graphRequirements(f, limits.Requirements-graph.Requirements)
			if err != nil {
				return nil, err
			}
			graph.Requirements += len(requires)
			graph.MetadataBytes += int64(len(raw))
			index = len(graph.Inputs)
			inputs[v.coordinate] = index
			graph.Inputs = append(graph.Inputs, GraphInput{GraphSelection: GraphSelection{v.coordinate, source},
				GoVersion: goVersion, GoModSHA256: crypt.Digest(raw), Bytes: int64(len(raw)), Requirements: requires})
		}
		input := graph.Inputs[index]
		unpruned := v.unpruned || !graphPruned(input.GoVersion)
		for _, required := range input.Requirements {
			if err := add(required, unpruned, unpruned); err != nil {
				return nil, err
			}
		}
	}
	usedSources := map[Coordinate]string{}
	for path, version := range selected {
		logical := Coordinate{path, version}
		source := resolveSource(logical)
		if other, exists := usedSources[source]; exists && other != path {
			return nil, ErrModule
		}
		usedSources[source] = path
		graph.BuildList = append(graph.BuildList, GraphSelection{logical, source})
	}
	slices.SortFunc(graph.BuildList, func(a, b GraphSelection) int { return strings.Compare(a.Logical.Module, b.Logical.Module) })
	slices.SortFunc(graph.Inputs, func(a, b GraphInput) int {
		if n := strings.Compare(a.Logical.Module, b.Logical.Module); n != 0 {
			return n
		}
		return semver.Compare(a.Logical.Version, b.Logical.Version)
	})
	return graph, nil
}

func graphGoVersion(f *modfile.File) (string, error) {
	goVersion := "1.16" // An absent directive predates pruning.
	if f.Go != nil {
		goVersion = f.Go.Version
	}
	if len(goVersion) > 64 || !version.IsValid("go"+goVersion) {
		return "", ErrModule
	}
	return goVersion, nil
}

func graphPruned(goVersion string) bool { return version.Compare("go"+goVersion, "go1.17") >= 0 }

func graphRequirements(f *modfile.File, maximum int) ([]Coordinate, error) {
	if len(f.Require) > maximum {
		return nil, ErrGraphLimit
	}
	result := make([]Coordinate, 0, len(f.Require))
	seen := map[string]bool{}
	for _, r := range f.Require {
		c, err := Canonical(r.Mod.Path, r.Mod.Version)
		if err != nil || seen[c.Module] {
			return nil, ErrModule
		}
		seen[c.Module] = true
		result = append(result, c)
	}
	slices.SortFunc(result, func(a, b Coordinate) int { return strings.Compare(a.Module, b.Module) })
	return result, nil
}
