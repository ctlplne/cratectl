// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
)

func goArtifactFixture() []Artifact {
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0"}
	m := GoModuleMetadata{Profile: GoModuleProfile, Module: c.Module, Version: c.Version, Digests: map[string]string{"zip": strings.Repeat("a", 64), "mod": strings.Repeat("b", 64), "info": strings.Repeat("c", 64)}}
	raw, _ := json.Marshal(m)
	as := []Artifact{}
	for _, kind := range []string{"zip", "mod", "info"} {
		as = append(as, Artifact{Path: c.Prefix() + "." + kind, Digest: m.Digests[kind], MediaType: goMedia[kind], Metadata: raw})
	}
	return as
}
func TestGoBundleRequiresAllExactRepresentations(t *testing.T) {
	original := goArtifactFixture()
	if _, e := validateGoModuleBundle(original); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name   string
		change func([]Artifact) []Artifact
	}{
		{"missing", func(as []Artifact) []Artifact { return as[:2] }},
		{"duplicate", func(as []Artifact) []Artifact { as[2] = as[0]; return as }},
		{"digest", func(as []Artifact) []Artifact { as[1].Digest = strings.Repeat("a", 64); return as }},
		{"media", func(as []Artifact) []Artifact { as[0].MediaType = "application/octet-stream"; return as }},
		{"alias", func(as []Artifact) []Artifact {
			as[0].Path = strings.Replace(as[0].Path, "!owned", "Owned", 1)
			return as
		}},
		{"unvalidated", func(as []Artifact) []Artifact { as[1].Metadata = []byte(`{}`); return as }},
		{"inconsistent", func(as []Artifact) []Artifact {
			var m GoModuleMetadata
			json.Unmarshal(as[1].Metadata, &m)
			m.Digests["zip"] = strings.Repeat("d", 64)
			as[1].Metadata, _ = json.Marshal(m)
			return as
		}},
		{"oversized", func(as []Artifact) []Artifact { as[0].Metadata = make([]byte, MaxGoModuleMetadata+1); return as }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := validateGoModuleBundle(tc.change(slices.Clone(original))); !errors.Is(e, ErrGoModuleUnvalidated) {
				t.Fatal(e)
			}
		})
	}
}
