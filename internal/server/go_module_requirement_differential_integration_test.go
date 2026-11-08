//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import "ctlplne.dev/cratectl/internal/gomodule"

type nativeRequirementDifferential struct {
	Name     string
	Main     []byte
	Inputs   []gomodule.RequirementInput
	Expected []gomodule.GraphSelection
}

// Expected selections are explicit independent oracles. In particular, the
// logical replacement order is the reverse of the physical source order, and
// an excluded transitive edge does not impose a floor on an unrelated root.
func nativeRequirementDifferentials() []nativeRequirementDifferential {
	original := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/aa-original", Version: "v1.0.0"}
	fork := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/zz-fork", Version: "v1.2.0"}
	leaf := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/mm-leaf", Version: "v1.0.0"}
	mod := func(c gomodule.Coordinate, goVersion, suffix string) []byte {
		return []byte("module " + c.Module + "\ngo " + goVersion + "\n" + suffix)
	}
	main := func(requirements string) []byte {
		return []byte("module go.cratectl.invalid/owned-differential\ngo 1.27.0\n" + requirements)
	}
	require := func(c gomodule.Coordinate) string { return "require " + c.Module + " " + c.Version + "\n" }
	forkMod := mod(fork, "1.16", require(leaf)+"replace "+leaf.Module+" => /never/read/this/path\nexclude "+leaf.Module+" "+leaf.Version+"\n")
	specificMain := append(main(require(original)), []byte("replace "+original.Module+" => go.cratectl.invalid/Owned/unpublished v1.0.0\nreplace "+original.Module+" "+original.Version+" => "+fork.Module+" "+fork.Version+"\n")...)
	wildcardMain := append(main(require(original)), []byte("replace "+original.Module+" => "+fork.Module+" "+fork.Version+"\n")...)
	replacementInputs := []gomodule.RequirementInput{{Source: fork, Mod: forkMod}, {Source: leaf, Mod: mod(leaf, "1.26.0", "")}}
	replacementExpected := []gomodule.GraphSelection{{Logical: original, Source: fork}, {Logical: leaf, Source: leaf}}
	a := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/aa-branch", Version: "v1.0.0"}
	b1 := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/mm-excluded", Version: "v1.0.0"}
	b2 := gomodule.Coordinate{Module: b1.Module, Version: "v1.1.0"}
	lower := gomodule.Coordinate{Module: b1.Module, Version: "v0.9.0"}
	z := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/zz-selector", Version: "v1.0.0"}
	exclude := "exclude " + b1.Module + " " + b1.Version + "\n"
	aInput := gomodule.RequirementInput{Source: a, Mod: mod(a, "1.16", require(b1))}
	return []nativeRequirementDifferential{
		{Name: "specific", Main: specificMain, Inputs: replacementInputs, Expected: replacementExpected},
		{Name: "wildcard", Main: wildcardMain, Inputs: replacementInputs, Expected: replacementExpected},
		{Name: "exclusion", Main: main(require(a) + require(z) + exclude),
			Inputs:   []gomodule.RequirementInput{aInput, {Source: z, Mod: mod(z, "1.16", require(b2))}, {Source: b2, Mod: mod(b2, "1.26.0", "")}},
			Expected: []gomodule.GraphSelection{{Logical: a, Source: a}, {Logical: b2, Source: b2}, {Logical: z, Source: z}}},
		{Name: "excluded-only", Main: main(require(a) + exclude), Inputs: []gomodule.RequirementInput{aInput},
			Expected: []gomodule.GraphSelection{{Logical: a, Source: a}}},
		{Name: "excluded-lower", Main: main(require(a) + require(lower) + exclude),
			Inputs:   []gomodule.RequirementInput{aInput, {Source: lower, Mod: mod(lower, "1.26.0", "")}},
			Expected: []gomodule.GraphSelection{{Logical: a, Source: a}, {Logical: lower, Source: lower}}},
	}
}
