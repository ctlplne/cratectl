// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestUniqueDependenciesPreserveFirstDeclarationsAndDistinctSemantics(t *testing.T) {
	for _, tc := range []struct {
		left, right, rangeLeft, rangeRight, flagsLeft, flagsRight string
		count                                                     int
	}{
		{"Owned.A", "owned.a", "1", "1.0.0", "", "", 1},
		{"Owned.µ", "Owned.Μ", "1", "1", "", "", 1},
		{"Owned.K", "Owned.K", "1", "1", "", "", 2},
		{"Owned.ſ", "Owned.S", "1", "1", "", "", 2},
		{"Owned.ı", "Owned.I", "1", "1", "", "", 2},
		{"Owned.A", "Owned.A", "1.0--0", "1.0-0", "", "", 2},
		{"Owned.A", "Owned.A", "1.0+First", "1.0+Second", "", "", 1},
		{"Owned.A", "Owned.A", "1.*", "[1.0.0, )", "", "", 1},
		{"Owned.A", "Owned.A", "1.2*", "1.*", "", "", 2},
		{"Owned.A", "owned.a", "1", "1.0", "Runtime, build,runtime", "BUILD,RUNTIME", 1},
		{"Owned.A", "Owned.A", "1", "1", "", " ", 2},
		{"Owned.A", "Owned.A", "1", "1", "Runtime", "Compile", 2},
	} {
		input := NuspecDependencies{Groups: []NuspecDependencyGroup{{Dependencies: []NuspecDependency{{ID: tc.left, RawRange: tc.rangeLeft, Include: tc.flagsLeft}, {ID: tc.right, RawRange: tc.rangeRight, Include: tc.flagsRight}}}}}
		original := append([]NuspecDependency{}, input.Groups[0].Dependencies...)
		out, e := UniqueNuspecDependencies(context.Background(), input)
		if e != nil || len(out.Groups) != 1 || len(out.Groups[0].Dependencies) != tc.count || out.Groups[0].Dependencies[0].ID != tc.left || out.Groups[0].Dependencies[0].RawRange != tc.rangeLeft || !reflect.DeepEqual(input.Groups[0].Dependencies, original) {
			t.Fatal(tc, out, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, e := UniqueNuspecDependencies(ctx, NuspecDependencies{}); !errors.Is(e, context.Canceled) || out.Groups != nil {
		t.Fatal("cancelled projection returned data", out, e)
	}
	for _, input := range []NuspecDependencies{{Groups: make([]NuspecDependencyGroup, MaxNuspecDependencyGroups+1)}, {Groups: []NuspecDependencyGroup{{Dependencies: []NuspecDependency{{ID: "Owned.A", RawRange: "invalid"}}}}}, {Groups: []NuspecDependencyGroup{{Dependencies: []NuspecDependency{{ID: "Owned.A", Include: strings.Repeat("x", MaxNuspecDependencyFieldBytes+1)}}}}}} {
		if out, e := UniqueNuspecDependencies(context.Background(), input); e == nil || out.Groups != nil {
			t.Fatal("invalid projection returned partial output", e)
		}
	}
}
