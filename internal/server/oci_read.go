// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"ctlplne.dev/cratectl/internal/store"
	"errors"
)

func (s *Server) resolveOCI(ctx context.Context, i store.Identity, endpoint store.Repository, image, kind, ref string, force bool) (resolvedArtifact, error) {
	retrySource := ""
	for attempt := 0; attempt < 2; attempt++ {
		sources, e := s.DB.NativeRepositories(ctx, i, endpoint.Name, image, "oci")
		if e != nil {
			return resolvedArtifact{}, e
		}
		retry := false
		for _, source := range sources {
			result := resolvedArtifact{source: source}
			if ociDigest.MatchString(ref) {
				if e = s.DB.CheckOCIDigestDecision(ctx, i, source.Name, ref); e != nil {
					return result, e
				}
			}
			if source.Mode == "proxy" {
				result, e = s.resolveProxy(ctx, i, source, image+"/"+kind+"/"+ref, force || retrySource == source.Name)
			} else {
				result.artifact, _, e = s.DB.OCISelection(ctx, i, source.Name, image, kind, ref)
			}
			if errors.Is(e, store.ErrNotFound) {
				e = nil
				continue
			}
			if e != nil {
				return result, e
			}
			a, selected, err := s.DB.OCISelection(ctx, i, endpoint.Name, image, kind, ref, result.admissions...)
			if errors.Is(err, store.ErrOCICacheExpired) && attempt == 0 {
				retrySource = source.Name
				retry = true
				break
			}
			if err != nil {
				return result, err
			}
			if a.Digest != result.artifact.Digest || selected.Name != source.Name {
				return result, store.ErrConflict
			}
			result.artifact = a
			result.ociImage = image
			result.ociRef = ref
			if endpoint.Mode == "group" {
				result.groups = []string{endpoint.Name}
			}
			return result, nil
		}
		if !retry {
			return resolvedArtifact{}, store.ErrNotFound
		}
	}
	return resolvedArtifact{}, store.ErrOCICacheExpired
}
func (s *Server) refreshOCIDiscovery(ctx context.Context, i store.Identity, repo store.Repository, image, kind, ref string, force bool) ([]store.OCIAdmission, error) {
	admissions := []store.OCIAdmission{}
	sources, e := s.DB.NativeRepositories(ctx, i, repo.Name, image, "oci")
	if e != nil {
		return admissions, e
	}
	for _, source := range sources {
		if source.Mode != "proxy" {
			continue
		}
		suffix := "tags"
		if kind == "referrers" {
			suffix = "referrers/" + ref
		}
		result, err := s.resolveProxy(ctx, i, source, "oci-catalog/"+image+"/"+suffix, force)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return admissions, err
		}
		admissions = append(admissions, result.admissions...)
	}
	return admissions, nil
}

func (s *Server) ociDiscovery(ctx context.Context, i store.Identity, repo store.Repository, image, kind, ref, filter string, force bool) ([]string, []store.OCIReferrer, error) {
	for attempt := 0; attempt < 2; attempt++ {
		admissions, e := s.refreshOCIDiscovery(ctx, i, repo, image, kind, ref, force || attempt > 0)
		if e != nil {
			return nil, nil, e
		}
		limit := s.NativeVersionLimit
		if kind == "tags/list" {
			limit = s.NativeTagLimit
		}
		tags, refs, e := s.DB.OCIDiscovery(ctx, i, repo.Name, image, kind, ref, filter, limit, s.NativeMetadataBytes, admissions...)
		if errors.Is(e, store.ErrOCICacheExpired) && attempt == 0 {
			continue
		}
		return tags, refs, e
	}
	return nil, nil, store.ErrOCICacheExpired
}
