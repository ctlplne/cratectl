// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func requirementProofFixture(t *testing.T) ([]byte, map[Coordinate][]byte, []byte, *RequirementGraph) {
	t.Helper()
	a1, a2 := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/a", "v1.1.0"}
	b, c1, c2 := Coordinate{"example.invalid/b", "v1.0.0"}, Coordinate{"example.invalid/c", "v1.0.0"}, Coordinate{"example.invalid/c", "v1.2.0"}
	files := map[Coordinate][]byte{a1: graphMod(a1.Module, "1.16", c2.Module+" "+c2.Version), a2: graphMod(a2.Module, "1.16", c1.Module+" "+c1.Version),
		b: graphMod(b.Module, "1.16", a2.Module+" "+a2.Version), c1: graphMod(c1.Module, "1.16"), c2: graphMod(c2.Module, "1.16", a1.Module+" "+a1.Version)}
	main := graphMod("owned/main", "1.16", a1.Module+" "+a1.Version, b.Module+" "+b.Version)
	inputs := []RequirementInput{}
	for c, mod := range files {
		inputs = append(inputs, RequirementInput{c, mod})
	}
	raw, g, err := BuildRequirementProof(context.Background(), main, inputs)
	if err != nil {
		t.Fatal(err)
	}
	return main, files, raw, g
}

func TestRequirementProofRetainsLowerVersionsAndRebuildsOnlyExactOriginals(t *testing.T) {
	main, files, raw, graph := requirementProofFixture(t)
	p, err := ParseRequirementProof(raw)
	if err != nil || len(p.Sources) != 5 || len(p.Selected) != 3 {
		t.Fatal("lower input lost", p, err)
	}
	load, loaded := graphFixture(t, files)
	verified, err := VerifyRequirementProof(context.Background(), raw, main, load, graph.BuildList)
	if err != nil || len(*loaded) != 5 || !slices.Equal(verified.BuildList, graph.BuildList) || len(verified.Inputs) != 5 {
		t.Fatal("original graph proof failed", verified, *loaded, err)
	}
	inputs := []RequirementInput{}
	for n := len(p.Sources) - 1; n >= 0; n-- {
		s := p.Sources[n]
		c := Coordinate{s.Module, s.Version}
		inputs = append(inputs, RequirementInput{c, files[c]})
	}
	repeated, _, err := BuildRequirementProof(context.Background(), main, inputs)
	if err != nil || !bytes.Equal(raw, repeated) {
		t.Fatal("input order changed canonical proof", err)
	}
}

func TestRequirementProofReplacementPreservesLogicalOrderAndExactPhysicalOriginals(t *testing.T) {
	original := Coordinate{"example.invalid/aa-original", "v1.0.0"}
	fork := Coordinate{"example.invalid/zz-fork", "v1.2.0"}
	leaf := Coordinate{"example.invalid/mm-leaf", "v1.0.0"}
	main := append(graphMod("owned/main", "1.27.0", original.Module+" "+original.Version),
		[]byte("replace "+original.Module+" => example.invalid/unused v1.0.0\nreplace "+original.Module+" "+original.Version+" => "+fork.Module+" "+fork.Version+"\n")...)
	files := map[Coordinate][]byte{
		fork: append(graphMod(fork.Module, "1.16", leaf.Module+" "+leaf.Version),
			[]byte("replace "+leaf.Module+" => /never/read/this/path\nexclude "+leaf.Module+" "+leaf.Version+"\n")...),
		leaf: graphMod(leaf.Module, "1.26.0"),
	}
	raw, graph, err := BuildRequirementProof(context.Background(), main, []RequirementInput{{fork, files[fork]}, {leaf, files[leaf]}})
	want := []GraphSelection{{original, fork}, {leaf, leaf}}
	if err != nil || !slices.Equal(graph.BuildList, want) {
		t.Fatal("replacement or dependency-local directives changed logical selection", graph, err)
	}
	proof, err := ParseRequirementProof(raw)
	if err != nil || len(proof.Sources) != 2 || proof.Sources[0].Module != leaf.Module || proof.Sources[1].Module != fork.Module ||
		len(proof.Selected) != 2 || proof.Selected[0].Module != original.Module || proof.Selected[0].SourceModule != fork.Module || proof.Selected[1].Module != leaf.Module {
		t.Fatal("physical input ordering was confused with logical selected ordering", proof, err)
	}
	load, loaded := graphFixture(t, files)
	verified, err := VerifyRequirementProof(context.Background(), raw, main, load, want)
	if err != nil || !slices.Equal(verified.BuildList, want) || !slices.Equal(*loaded, []Coordinate{fork, leaf}) {
		t.Fatal("replacement proof read logical/unused/local paths or lost exact originals", verified, *loaded, err)
	}
}

func TestRequirementProofRetainsDistinctCanonicalBuildSuffixVersions(t *testing.T) {
	a := Coordinate{"example.invalid/a", "v1.0.0"}
	compat := Coordinate{a.Module, "v1.0.0+incompatible"}
	b := Coordinate{"example.invalid/b", "v1.0.0"}
	main := graphMod("owned/main", "1.16", a.Module+" "+a.Version, b.Module+" "+b.Version)
	inputs := []RequirementInput{{a, graphMod(a.Module, "1.16")}, {compat, graphMod(a.Module, "1.16")},
		{b, graphMod(b.Module, "1.16", compat.Module+" "+compat.Version)}}
	raw, graph, err := BuildRequirementProof(context.Background(), main, inputs)
	if err != nil {
		t.Fatal("distinct canonical examined versions lost", err)
	}
	p, err := ParseRequirementProof(raw)
	if err != nil || len(p.Sources) != 3 || p.Sources[0].Version != a.Version || p.Sources[1].Version != compat.Version {
		t.Fatal("canonical suffix ordering is ambiguous", p, err)
	}
	files := map[Coordinate][]byte{}
	for _, input := range inputs {
		files[input.Source] = input.Mod
	}
	load, _ := graphFixture(t, files)
	if verified, err := VerifyRequirementProof(context.Background(), raw, main, load, graph.BuildList); err != nil || verified == nil || len(verified.Inputs) != 3 {
		t.Fatal("complete original suffix inputs did not replay", err)
	}
}

func TestRequirementProofRejectsChangedMissingCancelledOrMismatchedInputsWithoutPartialGraph(t *testing.T) {
	main, files, raw, graph := requirementProofFixture(t)
	for _, scenario := range []string{"main", "late_source", "missing", "cancelled", "selection"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			load, _ := graphFixture(t, files)
			project := slices.Clone(main)
			expected := slices.Clone(graph.BuildList)
			denied := errors.New("owned input permission refused")
			switch scenario {
			case "main":
				project = bytes.Replace(project, []byte("owned/main"), []byte("owned/else"), 1)
			case "selection":
				expected[0].Logical.Version = "v1.9.0"
			case "cancelled":
				cancel()
			case "missing", "late_source":
				original := load
				load = func(ctx context.Context, c Coordinate, maximum int64) ([]byte, error) {
					if c == (Coordinate{"example.invalid/c", "v1.0.0"}) {
						if scenario == "missing" {
							return nil, denied
						}
						// Same length and same legacy graph semantics: the original
						// byte digest must still refuse this changed metadata.
						return bytes.Replace(slices.Clone(files[c]), []byte("1.16"), []byte("1.15"), 1), nil
					}
					return original(ctx, c, maximum)
				}
			}
			got, err := VerifyRequirementProof(ctx, raw, project, load, expected)
			if err == nil || got != nil {
				t.Fatal("refusal leaked a partial proof", got, err)
			}
			if scenario == "missing" && !errors.Is(err, denied) {
				t.Fatal("permission failure replaced with a success-shaped graph", err)
			}
		})
	}
}

func TestRequirementProofPruningRejectsUnexpectedPrivateInputsAndClosureClaims(t *testing.T) {
	a, b := Coordinate{"example.invalid/a", "v1.0.0"}, Coordinate{"example.invalid/b", "v1.0.0"}
	main := graphMod("owned/main", "1.26.0", a.Module+" "+a.Version)
	mod := graphMod(a.Module, "1.26.0", b.Module+" "+b.Version)
	raw, g, err := BuildRequirementProof(context.Background(), main, []RequirementInput{{a, mod}})
	if err != nil || len(g.Inputs) != 1 || len(g.BuildList) != 2 {
		t.Fatal("modern pruning changed", g, err)
	}
	extra := []RequirementInput{{a, mod}, {b, graphMod(b.Module, "1.26.0")}}
	if p, g, err := BuildRequirementProof(context.Background(), main, extra); err == nil || p != nil || g != nil {
		t.Fatal("unexamined input would be transported")
	}
	if _, err := ParseRequirementProof(bytes.Replace(raw, []byte(`"profile":`), []byte(`"dependency_closure":true,"profile":`), 1)); err == nil {
		t.Fatal("proof conferred an unreviewed grant")
	}
	p, _ := ParseRequirementProof(raw)
	p.Sources = append(p.Sources, RequirementSource{b.Module, b.Version, RequirementObject{strings.Repeat("a", 64), 1}})
	changed, err := p.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	load, _ := graphFixture(t, map[Coordinate][]byte{a: mod})
	if got, err := VerifyRequirementProof(context.Background(), changed, main, load, g.BuildList); err == nil || got != nil {
		t.Fatal("unused indexed metadata accepted")
	}
}

func TestRequirementProofCanonicalDecoderRefusesAmbiguityAndCardinality(t *testing.T) {
	_, _, raw, _ := requirementProofFixture(t)
	for _, changed := range [][]byte{nil, []byte("null"), append(slices.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"profile":`), []byte(`"profile":"duplicate","profile":`), 1),
		bytes.Replace(raw, []byte(`"main_go_mod":`), []byte(`"MainGoMod":`), 1), bytes.Replace(raw, []byte(`"sha256":`), []byte(`"unknown":true,"sha256":`), 1),
		[]byte(strings.Repeat(" ", MaxRequirementProof+1)), []byte(`{"sources":[` + strings.Repeat(`{},`, MaxRequirementProofSources) + `{}]}`),
		[]byte(`{"selected":[` + strings.Repeat(`{},`, MaxRequirementProofSelections) + `{}]}`)} {
		if _, err := ParseRequirementProof(changed); err == nil {
			t.Fatal("ambiguous or over-budget proof admitted")
		}
	}
}

func FuzzRequirementProof(f *testing.F) {
	a := Coordinate{"example.invalid/a", "v1.0.0"}
	mod := graphMod(a.Module, "1.26.0")
	main := graphMod("owned/main", "1.26.0", a.Module+" "+a.Version)
	raw, g, err := BuildRequirementProof(context.Background(), main, []RequirementInput{{a, mod}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw, main)
	f.Add([]byte("null"), main)
	f.Add([]byte(`{"sources":[{}]}`), []byte{})
	f.Fuzz(func(t *testing.T, proof, project []byte) {
		if len(proof) > 64<<10 || len(project) > 32<<10 {
			return
		}
		loads := 0
		graph, err := VerifyRequirementProof(context.Background(), proof, project, func(_ context.Context, c Coordinate, maximum int64) ([]byte, error) {
			loads++
			if loads > MaxRequirementProofSources || maximum < 1 || maximum > MaxGoMod {
				t.Fatal("loader budget escaped")
			}
			if c != a {
				return nil, ErrRequirementProof
			}
			return mod, nil
		}, g.BuildList)
		if err != nil {
			if graph != nil {
				t.Fatal("failed proof exposed partial graph")
			}
			return
		}
		if graph == nil || !slices.Equal(graph.BuildList, g.BuildList) {
			t.Fatal("proof changed independently selected set")
		}
	})
}
