// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"net/http"

	"ctlplne.dev/cratectl/internal/cargo"
	"ctlplne.dev/cratectl/internal/store"
)

// Store selection stops at an unresolved earlier proxy. Refresh only that
// source, then ask the store for a fresh ordered view before going any lower.
func (s *Server) cargoReadRoute(r *http.Request, i store.Identity, repo store.Repository, name string) (store.Repository, *store.CargoGroupRoute, error) {
	if repo.Mode != "group" {
		return repo, nil, nil
	}
	key, err := cargo.NameKey(name)
	if err != nil {
		return repo, nil, store.ErrNotFound
	}
	var admissions []store.NativeAdmission
	var force map[string]bool
	if forceRefresh(r) {
		force = map[string]bool{}
	}
	refreshed := map[string]bool{}
	for count := 0; count <= 32; count++ {
		route, err := s.DB.CargoGroupMember(r.Context(), i, repo.Name, name, repo.SourceRevision, force, admissions)
		if err == nil {
			return route.Member, &route, nil
		}
		var request *store.CargoGroupRefresh
		if !errors.As(err, &request) {
			return repo, nil, err
		}
		if refreshed[request.Source.Name] {
			return repo, nil, store.ErrBusy
		}
		resolved, err := s.resolveProxy(r.Context(), i, request.Source, store.CargoCatalogPath(key), force != nil)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return repo, nil, err
		}
		admissions = append(admissions, resolved.admissions...)
		refreshed[request.Source.Name] = true
		if force != nil {
			force[request.Source.Name] = true
		}
	}
	return repo, nil, store.ErrMetadataLimit
}

func (s *Server) resolveCargoCatalog(r *http.Request, i store.Identity, source store.Repository, name string, route *store.CargoGroupRoute) (resolvedArtifact, error) {
	if route == nil {
		return s.resolveProxy(r.Context(), i, source, store.CargoCatalogPath(name), forceRefresh(r))
	}
	// The group has already refreshed the source if needed. The final group
	// read rechecks every earlier absence and this binding in one SQL snapshot.
	a, err := s.DB.NativeCatalogArtifact(r.Context(), i, source.Name, name, "cargo", store.CargoCatalogMedia)
	return resolvedArtifact{artifact: a, source: source, admissions: route.Admissions}, err
}
