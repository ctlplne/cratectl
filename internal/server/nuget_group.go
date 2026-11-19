// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"net/http"

	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) nugetGroupView(r *http.Request, i store.Identity, group store.Repository, id, version string) (store.NuGetGroupView, []store.NativeAdmission, error) {
	ctx := r.Context()
	var admissions []store.NativeAdmission
	visited := map[string]bool{}
	force := forceRefresh(r)
	var refreshed map[string]bool
	if force {
		refreshed = visited
	}
	for n := 0; n <= len(group.Settings.Members); n++ {
		view, err := s.DB.NuGetGroupVersions(ctx, i, group.Name, id, version, group.SourceRevision,
			s.NativeVersionLimit, s.NativeMetadataBytes, refreshed, admissions...)
		var refresh *store.NuGetGroupRefresh
		if !errors.As(err, &refresh) {
			return view, admissions, err
		}
		if visited[refresh.Source.Name] {
			return view, nil, store.ErrBusy
		}
		resolved, err := s.resolveProxy(ctx, i, refresh.Source, store.NuGetProxyCatalogPath(id), force)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return view, nil, err
		}
		admissions = append(admissions, resolved.admissions...)
		visited[refresh.Source.Name] = true
	}
	return store.NuGetGroupView{}, nil, store.ErrMetadataLimit
}

func (s *Server) resolveNuGetGroup(r *http.Request, i store.Identity, group store.Repository, id, version string) (resolvedArtifact, error) {
	view, admissions, err := s.nugetGroupView(r, i, group, id, version)
	if err != nil {
		return resolvedArtifact{}, err
	}
	result, err := s.resolve(r.Context(), i, view.Source, store.NuGetPath(id, version), forceRefresh(r))
	if err != nil {
		return result, err
	}
	result.groups = []string{group.Name}
	result.groupRevisions = map[string]int64{group.Name: group.SourceRevision}
	result.admissions = append(admissions, result.admissions...)
	return result, nil
}
