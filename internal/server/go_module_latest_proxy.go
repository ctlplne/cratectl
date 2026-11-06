// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

// Fetch only the configured proxy's latest advertisement. It does not fetch a
// package, approve its bytes, infer exact-version absence or consult VCS/sumdb.
// Completion must use the common current-authority/source/lease transaction.
func (s *Server) fetchGoModuleLatest(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) (store.RetrievalResult, error) {
	escaped, ok := strings.CutPrefix(lease.Path, "go-latest/")
	request, e := gomodule.ParseRequest(escaped + "/@latest")
	if !ok || e != nil || request.Operation != "latest" || store.GoModuleLatestPath(request.Module) != lease.Path || repo.Format != "go" || repo.Mode != "proxy" || repo.Name != lease.Repository || repo.SourceRevision != lease.SourceRevision || repo.Settings.Upstream == nil || s.Blobs == nil || s.NativeMetadataBytes < 1 {
		return store.RetrievalResult{}, store.ErrGoModuleUnvalidated
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	config := *repo.Settings.Upstream
	credential, e := s.credential(i.Tenant, config)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	endpoint, e := upstream.New(config, credential, s.PrivateUpstreamNetworks...)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	defer endpoint.Close()
	limit := min(s.NativeMetadataBytes, gomodule.MaxVersionInfo)
	object, data, fresh, stale, e := s.fetchGoRepresentation(ctx, i, repo, endpoint, escaped+"/@latest", limit, true)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	latest, e := store.NewGoModuleLatest(request.Module, data)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	metadata, e := json.Marshal(latest)
	if e != nil {
		return store.RetrievalResult{}, e
	}
	if object.Size+int64(len(metadata)) > limit {
		return store.RetrievalResult{}, store.ErrMetadataLimit
	}
	if e = ctx.Err(); e != nil {
		return store.RetrievalResult{}, e
	}
	return store.RetrievalResult{Status: 200, Object: &object, Metadata: metadata, MediaType: store.GoModuleLatestMedia, FreshSeconds: fresh, StaleSeconds: stale, GoLatest: &latest}, nil
}
