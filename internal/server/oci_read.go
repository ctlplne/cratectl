// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"ctlplne.dev/cratectl/internal/store"
	"errors"
)

func (s *Server) resolveOCI(ctx context.Context, i store.Identity, endpoint store.Repository, image, kind, ref string, force bool) (resolvedArtifact, error) {
	sources, e := s.DB.NativeRepositories(ctx, i, endpoint.Name, image, "oci")
	if e != nil {
		return resolvedArtifact{}, e
	}
	for _, source := range sources {
		result := resolvedArtifact{source: source}
		if source.Mode == "proxy" {
			if ociDigest.MatchString(ref) && !force {
				a, _, err := s.DB.OCISelection(ctx, i, source.Name, image, kind, ref)
				if err == nil {
					result.artifact = a
					result.cache = "hit"
				} else if !errors.Is(err, store.ErrNotFound) {
					return result, err
				}
			}
			if result.artifact.Digest == "" {
				result, e = s.resolveProxy(ctx, i, source, image+"/"+kind+"/"+ref, force)
			}
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
		a, selected, err := s.DB.OCISelection(ctx, i, endpoint.Name, image, kind, ref)
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
	return resolvedArtifact{}, store.ErrNotFound
}
func (s *Server) refreshOCIDiscovery(ctx context.Context, i store.Identity, repo store.Repository, image, kind, ref string, force bool) error {
	sources, e := s.DB.NativeRepositories(ctx, i, repo.Name, image, "oci")
	if e != nil {
		return e
	}
	for _, source := range sources {
		if source.Mode != "proxy" {
			continue
		}
		suffix := "tags"
		if kind == "referrers" {
			suffix = "referrers/" + ref
		}
		if _, e = s.resolveProxy(ctx, i, source, "oci-catalog/"+image+"/"+suffix, force); e != nil && !errors.Is(e, store.ErrNotFound) {
			return e
		}
	}
	return nil
}
