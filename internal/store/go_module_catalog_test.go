// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestGoModuleCatalogMetadataBoundsArrayAllocation(t *testing.T) {
	data := []byte(`{"versions":[` + strings.Repeat(`"",`, 350000) + `""]}`)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, e := ValidateGoModuleCatalogArtifact(Artifact{Metadata: data})
	runtime.ReadMemStats(&after)
	if !errors.Is(e, ErrGoModuleUnvalidated) || after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatal("catalog metadata array exceeded parser allocation budget", after.TotalAlloc-before.TotalAlloc, e)
	}
}

func TestGoModuleCatalogBindsRawListWithoutGrantingPackageApproval(t *testing.T) {
	mod := "go.cratectl.invalid/Owned/catalog"
	data := []byte("v1.1.0-beta\r\nv1.0.0\n")
	c, e := NewGoModuleCatalog(mod, data, 10, 4096)
	if e != nil || !slices.Equal(c.Versions, []string{"v1.0.0", "v1.1.0-beta"}) || c.ListDigest != crypt.Digest(data) || c.ListBytes != int64(len(data)) || GoModuleCatalogPath(mod) != "go-catalog/go.cratectl.invalid/!owned/catalog" {
		t.Fatal("raw source binding/canonical names", c, e)
	}
	raw, _ := json.Marshal(c)
	a := Artifact{Path: GoModuleCatalogPath(mod), Digest: c.ListDigest, Size: c.ListBytes, Metadata: raw, MediaType: GoModuleCatalogMedia, Decision: "unassessed"}
	if got, e := ValidateGoModuleCatalogArtifact(a); e != nil || got.Module != mod || a.Decision != "unassessed" {
		t.Fatal("advertisement changed approval", e)
	}
	if _, e = NewGoModuleCatalog(mod, data, 1, 4096); e == nil {
		t.Fatal("truncated over-budget catalog admitted")
	}
	if _, e = NewGoModuleCatalog(mod, nil, 10, 4096); e != nil {
		t.Fatal("legitimate empty source list rejected", e)
	}
	if _, e = NewGoModuleCatalog(mod, []byte("v1.0.0\nv1.1.0\nv1.0.0\n"), 10, 4096); e == nil {
		t.Fatal("late invalid source list returned a valid prefix")
	}
}

func TestGoModuleCatalogRetrievalRejectsUnboundAndMixedPublication(t *testing.T) {
	mod := "go.cratectl.invalid/Owned/catalog"
	c, e := NewGoModuleCatalog(mod, []byte("v1.0.0\nv1.1.0\n"), 10, 4096)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(c)
	repo := Repository{Name: "source", Format: "go", Mode: "proxy"}
	lease := Retrieval{Repository: repo.Name, Path: GoModuleCatalogPath(mod)}
	base := RetrievalResult{Status: 200, Object: &blob.Object{Digest: c.ListDigest, Size: c.ListBytes}, Metadata: raw, MediaType: GoModuleCatalogMedia, GoCatalog: &c, FreshSeconds: 60, StaleSeconds: 30}
	if e := validateGoModuleCatalogRetrieval(repo, lease, base); e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []string{"repository", "mode", "format", "path", "status", "missing-object", "digest", "size", "metadata", "typed-version", "unknown-profile", "duplicate-version", "unsorted", "pseudo-version", "mixed-go", "mixed-oci", "mixed-native", "mixed-npm", "freshness", "stale", "validator"} {
		t.Run(scenario, func(t *testing.T) {
			r, l, result := repo, lease, base
			object := *base.Object
			result.Object = &object
			catalog := *base.GoCatalog
			catalog.Versions = slices.Clone(catalog.Versions)
			result.GoCatalog = &catalog
			var mutateMetadata bool
			switch scenario {
			case "repository":
				l.Repository = "other"
			case "mode":
				r.Mode = "hosted"
			case "format":
				r.Format = "npm"
			case "path":
				l.Path = GoModuleCatalogPath("go.cratectl.invalid/other")
			case "status":
				result.Status = 304
			case "missing-object":
				result.Object = nil
			case "digest":
				result.Object.Digest = crypt.Digest([]byte("different"))
			case "size":
				result.Object.Size++
			case "metadata":
				result.Metadata = []byte(`{}`)
			case "typed-version":
				catalog.Versions = []string{"v1.0.0"}
			case "unknown-profile":
				catalog.Profile = "unknown"
				mutateMetadata = true
			case "duplicate-version":
				catalog.Versions = []string{"v1.0.0", "v1.0.0"}
				mutateMetadata = true
			case "unsorted":
				catalog.Versions = []string{"v1.1.0", "v1.0.0"}
				mutateMetadata = true
			case "pseudo-version":
				catalog.Versions = []string{"v0.0.0-20260102030405-0123456789ab"}
				mutateMetadata = true
			case "mixed-go":
				result.GoModule = &GoModulePublication{}
			case "mixed-oci":
				result.OCI = &OCIPublication{}
			case "mixed-native":
				result.NativeCatalog = &NativeCatalogPublication{}
			case "mixed-npm":
				result.NPMCatalog = &NPMCatalog{}
			case "freshness":
				result.FreshSeconds = 86401
			case "stale":
				result.StaleSeconds = -1
			case "validator":
				result.ETag = "zip-only"
			}
			if mutateMetadata {
				result.Metadata, _ = json.Marshal(catalog)
			}
			if e := validateGoModuleCatalogRetrieval(r, l, result); !errors.Is(e, ErrGoModuleUnvalidated) {
				t.Fatal("unbound catalog published", scenario, e)
			}
		})
	}
}

func FuzzGoModuleCatalogMetadata(f *testing.F) {
	c, e := NewGoModuleCatalog("go.cratectl.invalid/Owned/catalog", []byte("v1.0.0\n"), 10, 4096)
	if e != nil {
		f.Fatal(e)
	}
	raw, _ := json.Marshal(c)
	f.Add(raw)
	f.Add([]byte(`{"versions":[]}`))
	f.Add([]byte(`{"versions":["v1.0.0"],"versions":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		a := Artifact{Path: GoModuleCatalogPath(c.Module), Digest: c.ListDigest, Size: c.ListBytes, MediaType: GoModuleCatalogMedia, Metadata: data}
		got, e := ValidateGoModuleCatalogArtifact(a)
		if e != nil {
			return
		}
		a.Metadata, _ = json.Marshal(got)
		replay, e := ValidateGoModuleCatalogArtifact(a)
		if e != nil || replay.Module != got.Module || !slices.Equal(replay.Versions, got.Versions) || replay.ListDigest != got.ListDigest || replay.ListBytes != got.ListBytes {
			t.Fatal("valid advertisement changed meaning on canonical round trip", e)
		}
	})
}

func TestGoModuleCatalogRejectsAmbiguousMetadata(t *testing.T) {
	c, e := NewGoModuleCatalog("go.cratectl.invalid/Owned/catalog", []byte("v1.0.0\n"), 10, 4096)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(c)
	for _, data := range []string{
		strings.Replace(string(raw), `"versions":`, `"versions":[],"versions":`, 1),
		strings.Replace(string(raw), `"module":`, `"Module":`, 1),
		strings.Replace(string(raw), `"versions":`, `"unknown":0,"versions":`, 1),
		string(raw) + `{}`,
		strings.Replace(string(raw), `["v1.0.0"]`, `"v1.0.0"`, 1),
		strings.Replace(string(raw), `["v1.0.0"]`, `null`, 1),
	} {
		if _, e := decodeGoModuleCatalog([]byte(data)); !errors.Is(e, ErrGoModuleUnvalidated) {
			t.Fatal("ambiguous metadata admitted", e)
		}
	}
}
