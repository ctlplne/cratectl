// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

// Prepare every consulted advertisement before asking the store for one complete
// current discovery snapshot. Package intake and approval remain independent.
// The whole preparation has one deadline and a running byte budget, with at most
// one bounded catalog read/fill able to discover that the budget is exceeded.
func (s *Server) prepareGoModuleView(parent context.Context, i store.Identity, repo store.Repository, mod string, force bool) (store.GoModuleVersionView, []store.NativeAdmission, error) {
	p := store.GoModuleCatalogPath(mod)
	escaped := strings.TrimPrefix(p, "go-catalog/")
	request, e := gomodule.ParseRequest(escaped + "/@v/list")
	if p == "" || e != nil || request.Module != mod || repo.Format != "go" {
		return store.GoModuleVersionView{}, nil, store.ErrGoModuleUnvalidated
	}
	if s.NativeVersionLimit < 1 || s.NativeVersionLimit > 10000 || s.NativeMetadataBytes < 1 || s.NativeMetadataBytes > 64<<20 {
		return store.GoModuleVersionView{}, nil, store.ErrMetadataLimit
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	sources, e := s.DB.NativeRepositories(ctx, i, repo.Name, escaped, "go")
	if e != nil {
		return store.GoModuleVersionView{}, nil, e
	}
	if len(sources) > 32 {
		return store.GoModuleVersionView{}, nil, store.ErrMetadataLimit
	}
	remaining := s.NativeMetadataBytes
	var admissions []store.NativeAdmission
	for _, source := range sources {
		if source.Mode == "hosted" {
			continue
		}
		if source.Mode != "proxy" {
			return store.GoModuleVersionView{}, nil, store.ErrConflict
		}
		if remaining < 192 {
			return store.GoModuleVersionView{}, nil, store.ErrMetadataLimit
		}
		a, err := s.resolveProxy(ctx, i, source, p, force)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.GoModuleVersionView{}, nil, err
		}
		remaining -= 192 + a.artifact.Size + int64(len(a.artifact.Path)+len(a.artifact.MediaType)+len(a.artifact.Metadata))
		if remaining < 0 {
			return store.GoModuleVersionView{}, nil, store.ErrMetadataLimit
		}
		admissions = append(admissions, a.admissions...)
		if len(admissions) > 32 {
			return store.GoModuleVersionView{}, nil, store.ErrMetadataLimit
		}
	}
	view, e := s.DB.GoModuleView(ctx, i, repo.Name, mod, s.NativeVersionLimit, s.NativeMetadataBytes, admissions...)
	if e != nil {
		return store.GoModuleVersionView{}, nil, e
	}
	return view, admissions, nil
}
