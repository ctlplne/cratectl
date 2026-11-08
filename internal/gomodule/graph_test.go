// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func graphMod(path, goVersion string, requirements ...string) []byte {
	text := "module " + path + "\n"
	if goVersion != "" {
		text += "go " + goVersion + "\n"
	}
	for _, r := range requirements {
		text += "require " + r + "\n"
	}
	return []byte(text)
}

func graphFixture(t *testing.T, files map[Coordinate][]byte) (GraphLoader, *[]Coordinate) {
	t.Helper()
	loaded := []Coordinate{}
	return func(ctx context.Context, c Coordinate, maximum int64) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		loaded = append(loaded, c)
		raw, ok := files[c]
		if !ok {
			return nil, errors.New("owned graph input missing")
		}
		if int64(len(raw)) > maximum {
			return nil, ErrGraphLimit
		}
		return raw, nil
	}, &loaded
}

func TestRequirementGraphLowerVersionsInfluenceSelectionAndCyclesTerminate(t *testing.T) {
	a1, a2 := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/a", "v1.1.0"}
	b, c1, c2 := Coordinate{"example.invalid/b", "v1.0.0"}, Coordinate{"example.invalid/c", "v1.0.0"}, Coordinate{"example.invalid/c", "v1.2.0"}
	files := map[Coordinate][]byte{
		a1: graphMod(a1.Module, "1.16", c2.Module+" "+c2.Version),
		a2: graphMod(a2.Module, "1.16", c1.Module+" "+c1.Version),
		b:  graphMod(b.Module, "1.16", a2.Module+" "+a2.Version),
		c1: graphMod(c1.Module, "1.16"),
		c2: graphMod(c2.Module, "1.16", a1.Module+" "+a1.Version),
	}
	load, loaded := graphFixture(t, files)
	main := graphMod("owned/main", "1.16", a1.Module+" "+a1.Version, b.Module+" "+b.Version)
	got, err := ResolveRequirements(context.Background(), main, load, DefaultGraphLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []GraphSelection{{a2, a2}, {b, b}, {c2, c2}}
	if !reflect.DeepEqual(got.BuildList, want) || got.Pruned || len(*loaded) != 5 || len(got.Inputs) != 5 {
		t.Fatalf("lost unselected-version requirement or cycle bound: %+v loads=%v", got, *loaded)
	}
	if got.MainGoModSHA256 != crypt.Digest(main) || got.Requirements != 6 {
		t.Fatal("main identity/complete examined edge inventory lost")
	}
	var total int64 = int64(len(main))
	for _, input := range got.Inputs {
		original := files[input.Source]
		if input.GoModSHA256 != crypt.Digest(original) || input.Bytes != int64(len(original)) {
			t.Fatal("examined graph input identity changed")
		}
		total += input.Bytes
	}
	if got.MetadataBytes != total {
		t.Fatal("metadata work not fully accounted")
	}
}

func TestRequirementGraphModernPruningAndLegacySubgraphs(t *testing.T) {
	a, b, c := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/b", "v1.0.0"}, Coordinate{"example.invalid/c", "v1.0.0"}
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			goVersion := "1.26.0"
			if legacy {
				goVersion = "1.16"
			}
			files := map[Coordinate][]byte{a: graphMod(a.Module, goVersion, b.Module+" "+b.Version),
				b: graphMod(b.Module, "1.26.0", c.Module+" "+c.Version), c: graphMod(c.Module, "1.26.0")}
			load, loaded := graphFixture(t, files)
			got, err := ResolveRequirements(context.Background(), graphMod("owned/main", "1.26.0", a.Module+" "+a.Version), load, DefaultGraphLimits())
			if err != nil {
				t.Fatal(err)
			}
			if legacy && (len(got.BuildList) != 3 || len(*loaded) != 3) || !legacy && (len(got.BuildList) != 2 || len(*loaded) != 1) {
				t.Fatalf("incorrect modern/legacy pruning: %+v %v", got, *loaded)
			}
		})
	}
}

func TestRequirementGraphRetainsToolchainFloorWithoutExecutingOrSelectingIt(t *testing.T) {
	a := Coordinate{"example.invalid/a", "v1.0.0"}
	load, _ := graphFixture(t, map[Coordinate][]byte{a: graphMod(a.Module, "1.28.2")})
	main := append(graphMod("owned/main", "1.26.0", a.Module+" "+a.Version), []byte("toolchain go1.27.3\n")...)
	got, err := ResolveRequirements(context.Background(), main, load, DefaultGraphLimits())
	if err != nil || got.MinimumGoVersion != "1.28.2" || got.SuggestedToolchain != "go1.27.3" || len(got.BuildList) != 1 {
		t.Fatal("required Go floor or inert main toolchain suggestion lost", got, err)
	}
}

func TestRequirementGraphPrunedNodeRevisitedThroughLegacyPath(t *testing.T) {
	a, b, z := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/b", "v1.0.0"}, Coordinate{"example.invalid/z", "v1.0.0"}
	files := map[Coordinate][]byte{a: graphMod(a.Module, "1.26.0", b.Module+" "+b.Version),
		b: graphMod(b.Module, "1.26.0"), z: graphMod(z.Module, "1.16", a.Module+" "+a.Version)}
	load, loaded := graphFixture(t, files)
	got, err := ResolveRequirements(context.Background(), graphMod("owned/main", "1.26.0", a.Module+" "+a.Version, z.Module+" "+z.Version), load, DefaultGraphLimits())
	if err != nil || len(*loaded) != 3 || len(got.Inputs) != 3 || got.Requirements != 4 {
		t.Fatalf("legacy revisit failed or counted/loaded input twice: %+v %v %v", got, *loaded, err)
	}
}

func TestRequirementGraphMainReplacementsAndDependencyDirectives(t *testing.T) {
	a, fork := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/fork", "v1.2.0"}
	b := Coordinate{"example.invalid/b", "v1.0.0"}
	main := append(graphMod("owned/main", "1.16", a.Module+" "+a.Version), []byte("replace example.invalid/a => example.invalid/unused v1.0.0\nreplace example.invalid/a v1.0.0 => example.invalid/fork v1.2.0\n")...)
	files := map[Coordinate][]byte{fork: append(graphMod(fork.Module, "1.16", b.Module+" "+b.Version),
		[]byte("replace example.invalid/b => /never/read/this/path\nexclude example.invalid/b v1.0.0\n")...), b: graphMod(b.Module, "1.16")}
	load, loaded := graphFixture(t, files)
	got, err := ResolveRequirements(context.Background(), main, load, DefaultGraphLimits())
	if err != nil || !reflect.DeepEqual(got.BuildList, []GraphSelection{{a, fork}, {b, b}}) || !reflect.DeepEqual(*loaded, []Coordinate{fork, b}) {
		t.Fatalf("main replacement or dependency-only directives changed: %+v %v %v", got, *loaded, err)
	}
	for _, directive := range []string{"replace example.invalid/a => ../private", "exclude example.invalid/a v1.0.0"} {
		load, loaded := graphFixture(t, files)
		got, err := ResolveRequirements(context.Background(), append(graphMod("owned/main", "1.16", a.Module+" "+a.Version), []byte(directive+"\n")...), load, DefaultGraphLimits())
		if !errors.Is(err, ErrGraphUnsupported) || got != nil || len(*loaded) != 0 {
			t.Fatal("local/unresolved main input escaped refusal", got, err)
		}
	}
}

func TestRequirementGraphMainExclusionFiltersTransitiveEdges(t *testing.T) {
	a, b1, b2, z := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/b", "v1.0.0"}, Coordinate{"example.invalid/b", "v1.1.0"}, Coordinate{"example.invalid/z", "v1.0.0"}
	files := map[Coordinate][]byte{a: graphMod(a.Module, "1.16", b1.Module+" "+b1.Version),
		z: graphMod(z.Module, "1.16", b2.Module+" "+b2.Version), b2: graphMod(b2.Module, "1.16")}
	load, loaded := graphFixture(t, files)
	main := append(graphMod("owned/main", "1.16", a.Module+" "+a.Version, z.Module+" "+z.Version), []byte("exclude example.invalid/b v1.0.0\n")...)
	got, err := ResolveRequirements(context.Background(), main, load, DefaultGraphLimits())
	if err != nil || len(*loaded) != 3 || got.BuildList[1].Logical != b2 {
		t.Fatal("excluded transitive version was loaded or silently substituted", got, *loaded, err)
	}
}

func TestRequirementGraphExcludedTransitiveEdgeDoesNotInventAReplacementVersion(t *testing.T) {
	a := Coordinate{"example.invalid/a", "v1.0.0"}
	b := Coordinate{"example.invalid/b", "v1.0.0"}
	lower := Coordinate{b.Module, "v0.9.0"}
	for _, keepLowerRoot := range []bool{false, true} {
		t.Run(fmt.Sprint(keepLowerRoot), func(t *testing.T) {
			main := graphMod("owned/main", "1.27.0", a.Module+" "+a.Version)
			files := map[Coordinate][]byte{a: graphMod(a.Module, "1.16", b.Module+" "+b.Version)}
			want := []GraphSelection{{a, a}}
			if keepLowerRoot {
				main = append(main, []byte("require "+lower.Module+" "+lower.Version+"\n")...)
				files[lower] = graphMod(lower.Module, "1.26.0")
				want = append(want, GraphSelection{lower, lower})
			}
			main = append(main, []byte("exclude "+b.Module+" "+b.Version+"\n")...)
			load, loaded := graphFixture(t, files)
			graph, err := ResolveRequirements(context.Background(), main, load, DefaultGraphLimits())
			if err != nil || !reflect.DeepEqual(graph.BuildList, want) || len(*loaded) != len(want) {
				t.Fatal("excluded metadata edge invented a catalog query or version floor", graph, *loaded, err)
			}
			// Metadata selection removes the excluded edge. Package discovery may
			// still require another version; this graph never asserts that closure.
			for _, c := range *loaded {
				if c == b {
					t.Fatal("excluded original was read")
				}
			}
		})
	}
}

func TestRequirementGraphDeniedMissingCancelledAndWorkLimitsNeverReturnPartial(t *testing.T) {
	a, b := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/b", "v1.0.0"}
	main := graphMod("owned/main", "1.16", a.Module+" "+a.Version)
	files := map[Coordinate][]byte{a: graphMod(a.Module, "1.16", b.Module+" "+b.Version), b: graphMod(b.Module, "1.16")}
	for _, kind := range []string{"denied", "missing", "cancelled", "modules", "versions", "requirements", "bytes", "oversized_loader", "wrong_module", "invalid_version"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			load, _ := graphFixture(t, files)
			limits := DefaultGraphLimits()
			sentinel := errors.New("owned permission refusal")
			switch kind {
			case "denied", "missing":
				original := load
				load = func(ctx context.Context, c Coordinate, maximum int64) ([]byte, error) {
					if c == b {
						return nil, sentinel
					}
					return original(ctx, c, maximum)
				}
			case "cancelled":
				original := load
				load = func(ctx context.Context, c Coordinate, maximum int64) ([]byte, error) {
					cancel()
					return original(ctx, c, maximum)
				}
			case "modules":
				limits.Modules = 1
			case "versions":
				limits.Versions = 1
			case "requirements":
				limits.Requirements = 1
			case "bytes":
				limits.MetadataBytes = int64(len(main)) + 1
			case "oversized_loader":
				load = func(context.Context, Coordinate, int64) ([]byte, error) {
					return []byte(strings.Repeat("x", MaxGoMod+1)), nil
				}
			case "wrong_module":
				load = func(context.Context, Coordinate, int64) ([]byte, error) {
					return graphMod("other.invalid/owned", "1.16"), nil
				}
			case "invalid_version":
				load = func(context.Context, Coordinate, int64) ([]byte, error) {
					return graphMod(a.Module, "1.16", b.Module+" v1"), nil
				}
			}
			got, err := ResolveRequirements(ctx, main, load, limits)
			if got != nil || err == nil {
				t.Fatal("failed graph returned a partial/complete result", got, err)
			}
			if (kind == "denied" || kind == "missing") && !errors.Is(err, sentinel) {
				t.Fatal("source authorization/missing-input failure lost", err)
			}
		})
	}
}
