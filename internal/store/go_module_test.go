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

func TestGoGroupSelectionRetainsBlockedFirstSourceCoordinates(t *testing.T) {
	mod := "go.cratectl.invalid/Owned/app"
	for _, reason := range []string{"denied", "unassessed", "deleted"} {
		first := goArtifactFixture()
		for index := range first {
			first[index].Decision = "allowed"
		}
		first[0].Decision = reason
		if reason == "deleted" {
			first[0].Decision = "allowed"
			first[0].Deleted = true
		}
		candidates, e := goModuleVersionCandidates(first, mod, true)
		if e != nil || candidates["v1.0.0"] {
			t.Fatal("blocked version lost", reason, candidates, e)
		}
		selected := map[string]bool{}
		mergeGoModuleVersions(selected, candidates)
		mergeGoModuleVersions(selected, map[string]bool{"v1.0.0": true, "v1.1.0": true})
		if selected["v1.0.0"] || !selected["v1.1.0"] {
			t.Fatal("lower source bypassed first authority", selected)
		}
	}
	first := goArtifactFixture()
	if candidates, e := goModuleVersionCandidates(first, mod, false); e != nil || !candidates["v1.0.0"] {
		t.Fatal("source's unassessed admission", e)
	}
	if candidates, e := goModuleVersionCandidates(first, mod, true); e != nil || candidates["v1.0.0"] {
		t.Fatal("group weakened review", e)
	}
	if _, e := goModuleVersionCandidates(first[:2], mod, false); !errors.Is(e, ErrGoModuleUnvalidated) {
		t.Fatal("partial source became absence", e)
	}
	if _, e := goModuleVersionCandidates(first, "go.cratectl.invalid/other", false); !errors.Is(e, ErrGoModuleUnvalidated) {
		t.Fatal("wrong namespace admitted", e)
	}
}
func TestGoRepositoryModesAdmitHostedGroupsAndRejectProxies(t *testing.T) {
	group := Repository{Name: "group", Format: "go", Mode: "group", Settings: RepositorySettings{Members: []string{"owned"}, NamespaceOwners: map[string]string{"go.cratectl.invalid/!owned/": "owned"}}}
	if e := ValidateRepository(&group); e != nil {
		t.Fatal("Go hosted group rejected", e)
	}
	proxy := Repository{Name: "proxy", Format: "go", Mode: "proxy"}
	if e := ValidateRepository(&proxy); e == nil {
		t.Fatal("unimplemented Go proxy admitted")
	}
}

func TestGoNamespacePinsAgreeForDiscoveryAndExactVersionReads(t *testing.T) {
	for _, prefix := range []string{"go.cratectl.invalid/!owned/", "go.cratectl.invalid/!owned/app/", "go.cratectl.invalid/"} {
		r := Repository{Name: "group", Format: "go", Mode: "group", Settings: RepositorySettings{Members: []string{"owned"}, NamespaceOwners: map[string]string{prefix: "owned"}}}
		if e := ValidateRepository(&r); e != nil {
			t.Fatal("canonical Go namespace prefix rejected", prefix, e)
		}
	}
	for _, prefix := range []string{"go.cratectl.invalid/Owned/", "go.cratectl.invalid/!owned/app/@v/", "go.cratectl.invalid/!owned/app/@latest/", "go.cratectl.invalid/!!/"} {
		r := Repository{Name: "group", Format: "go", Mode: "group", Settings: RepositorySettings{Members: []string{"owned"}, NamespaceOwners: map[string]string{prefix: "owned"}}}
		if e := ValidateRepository(&r); e == nil {
			t.Fatal("coordinate-specific or aliased namespace split discovery/read ownership", prefix)
		}
	}
}
