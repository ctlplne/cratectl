// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
)

func TestGoModuleLatestBindsOriginalAdvertisementWithoutPackageApproval(t *testing.T) {
	mod := "go.cratectl.invalid/Owned/latest"
	data := []byte("{\n \"Version\":\"v0.0.0-20260102030405-0123456789ab\", \"Origin\":{\"opaque\":true}\n}\n")
	c, e := NewGoModuleLatest(mod, data)
	if e != nil || c.Version != "v0.0.0-20260102030405-0123456789ab" || GoModuleLatestPath(mod) != "go-latest/go.cratectl.invalid/!owned/latest" {
		t.Fatal("latest lost canonical coordinate", e)
	}
	raw, _ := json.Marshal(c)
	a := Artifact{Path: GoModuleLatestPath(mod), Digest: c.InfoDigest, Size: c.InfoBytes, MediaType: GoModuleLatestMedia, Metadata: raw, Decision: "unassessed"}
	if got, e := ValidateGoModuleLatestArtifact(a); e != nil || got != c || a.Decision != "unassessed" {
		t.Fatal("latest changed byte binding or granted approval", e)
	}
	for _, attack := range []string{"path", "digest", "size", "media", "profile", "version", "alias", "duplicate", "unknown", "trailing", "oversized", "null"} {
		t.Run(attack, func(t *testing.T) {
			bad := a
			switch attack {
			case "path":
				bad.Path += "/other"
			case "digest":
				bad.Digest = strings.Repeat("0", 64)
			case "size":
				bad.Size++
			case "media":
				bad.MediaType = GoModuleCatalogMedia
			case "profile":
				bad.Metadata = []byte(strings.Replace(string(raw), GoModuleLatestProfile, "go-module-latest-v999", 1))
			case "version":
				bad.Metadata = []byte(strings.Replace(string(raw), c.Version, "v2.0.0", 1))
			case "alias":
				bad.Metadata = []byte(strings.Replace(string(raw), `"version"`, `"Version"`, 1))
			case "duplicate":
				bad.Metadata = []byte(strings.TrimSuffix(string(raw), "}") + `,"version":"v1.0.0"}`)
			case "unknown":
				bad.Metadata = []byte(strings.TrimSuffix(string(raw), "}") + `,"extra":null}`)
			case "trailing":
				bad.Metadata = append(append([]byte{}, raw...), []byte(" {}")...)
			case "oversized":
				bad.Metadata = []byte(strings.Repeat(" ", MaxGoModuleLatestMetadata+1))
			case "null":
				bad.Metadata = []byte(`null`)
			}
			if got, e := ValidateGoModuleLatestArtifact(bad); !errors.Is(e, ErrGoModuleUnvalidated) || got != (GoModuleLatest{}) {
				t.Fatal("unbound latest exposed partial advertisement", e)
			}
		})
	}
}

func TestGoModuleLatestRetrievalRejectsMixedAndUnboundReferences(t *testing.T) {
	mod := "go.cratectl.invalid/Owned/latest"
	c, e := NewGoModuleLatest(mod, []byte(`{"Version":"v1.0.0"}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(c)
	repo := Repository{Name: "owned", Format: "go", Mode: "proxy"}
	lease := Retrieval{Repository: repo.Name, Path: GoModuleLatestPath(mod)}
	base := RetrievalResult{Status: 200, Object: &blob.Object{Digest: c.InfoDigest, Size: c.InfoBytes}, Metadata: raw, MediaType: GoModuleLatestMedia, FreshSeconds: 30, GoLatest: &c}
	if e := validateGoModuleLatestRetrieval(repo, lease, base); e != nil {
		t.Fatal(e)
	}
	for _, attack := range []string{"bare304", "missing-object", "missing-typed", "catalog", "bundle", "oci", "generic-catalog", "npm", "source-binding", "metadata", "validator", "window", "failure"} {
		t.Run(attack, func(t *testing.T) {
			bad, l := base, lease
			switch attack {
			case "bare304":
				bad.Status = 304
			case "missing-object":
				bad.Object = nil
			case "missing-typed":
				bad.GoLatest = nil
			case "catalog":
				bad.GoCatalog = &GoModuleCatalog{}
			case "bundle":
				bad.GoModule = &GoModulePublication{}
			case "oci":
				bad.OCI = &OCIPublication{}
			case "generic-catalog":
				bad.NativeCatalog = &NativeCatalogPublication{}
			case "npm":
				bad.NPMCatalog = &NPMCatalog{}
			case "source-binding":
				l.Repository = "other"
			case "metadata":
				other := c
				other.Version = "v1.1.0"
				bad.GoLatest = &other
			case "validator":
				bad.ETag = "unbound-upstream-etag"
			case "window":
				bad.FreshSeconds = 86401
			case "failure":
				bad.Failure = "failed"
			}
			if e := validateGoModuleLatestRetrieval(repo, l, bad); !errors.Is(e, ErrGoModuleUnvalidated) {
				t.Fatal("latest admitted mixed or unbound intake", e)
			}
		})
	}
}
