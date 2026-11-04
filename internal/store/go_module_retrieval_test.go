// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"errors"
	"slices"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
)

func goRetrievalFixture() (Repository, Retrieval, RetrievalResult) {
	as := goArtifactFixture()
	repo := Repository{Name: "owned", Format: "go", Mode: "proxy"}
	lease := Retrieval{Repository: repo.Name, Path: as[0].Path}
	return repo, lease, RetrievalResult{Status: 200, Object: &blob.Object{Digest: as[0].Digest, Size: as[0].Size}, Metadata: as[0].Metadata, MediaType: as[0].MediaType, FreshSeconds: 60, GoModule: &GoModulePublication{Objects: as}}
}

func TestGoModuleRetrievalRequiresExactBundleRootAndSinglePublicationKind(t *testing.T) {
	r, l, result := goRetrievalFixture()
	if e := validateGoModuleRetrieval(r, l, result); e != nil {
		t.Fatal("complete canonical bundle rejected", e)
	}
	for _, change := range []struct {
		name string
		edit func(*Repository, *Retrieval, *RetrievalResult)
	}{
		{"wrong format", func(r *Repository, _ *Retrieval, _ *RetrievalResult) { r.Format = "generic" }},
		{"hosted", func(r *Repository, _ *Retrieval, _ *RetrievalResult) { r.Mode = "hosted" }},
		{"wrong repository", func(_ *Repository, l *Retrieval, _ *RetrievalResult) { l.Repository = "other" }},
		{"sibling lease", func(_ *Repository, l *Retrieval, _ *RetrievalResult) { l.Path = result.GoModule.Objects[1].Path }},
		{"bare raw object", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.GoModule = nil }},
		{"missing staged root", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.Object = nil }},
		{"partial bundle", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.GoModule.Objects = r.GoModule.Objects[:2] }},
		{"unbound bytes", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.Object.Digest = "changed" }},
		{"unbound size", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.Object.Size++ }},
		{"unbound media", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.MediaType = "text/plain" }},
		{"unbound metadata", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.Metadata = []byte(`{}`) }},
		{"negative size", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.GoModule.Objects[1].Size = -1 }},
		{"outside reference", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.GoModule.Objects[1].Repository = "other" }},
		{"mixed OCI", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.OCI = &OCIPublication{} }},
		{"mixed catalog", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.NativeCatalog = &NativeCatalogPublication{} }},
		{"mixed npm", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.NPMCatalog = &NPMCatalog{} }},
		{"mixed source", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.NPMSources = []NPMSource{{}} }},
		{"bare304", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.Status = 304 }},
		{"failed transfer", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.Failure = "upstream_transfer_failure" }},
		{"fresh budget", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.FreshSeconds = 86401 }},
		{"stale budget", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.StaleSeconds = -1 }},
		{"validator injection", func(_ *Repository, _ *Retrieval, r *RetrievalResult) { r.ETag = "bad\r\nheader" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r, l, result := goRetrievalFixture()
			result.GoModule.Objects = slices.Clone(result.GoModule.Objects)
			change.edit(&r, &l, &result)
			if e := validateGoModuleRetrieval(r, l, result); !errors.Is(e, ErrGoModuleUnvalidated) {
				t.Fatal("inconsistent intake admitted", e)
			}
		})
	}
}
