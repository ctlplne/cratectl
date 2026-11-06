// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func (s *Server) resolveGoModuleProxy(ctx context.Context, i store.Identity, repo store.Repository, p string, force bool) (resolvedArtifact, error) {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Version == "" {
		return resolvedArtifact{}, store.ErrGoModuleUnvalidated
	}
	root, e := s.resolveProxy(ctx, i, repo, request.Coordinate.Prefix()+".zip", force)
	if e != nil {
		return root, e
	}
	if request.Operation != "zip" {
		root.artifact, e = s.DB.GoModuleProxyArtifact(ctx, i, repo.Name, p, repo.SourceRevision, root.admissions...)
	}
	return root, e
}

func (s *Server) proxyAbsence(ctx context.Context, i store.Identity, repo store.Repository, p string, admissions ...store.NativeAdmission) error {
	if repo.Format == "go" && !goModuleAdvertisementPath(p) {
		absent, e := s.DB.GoModuleProxyAbsent(ctx, i, repo.Name, p, repo.SourceRevision, admissions...)
		if e != nil {
			return e
		}
		if !absent {
			return store.ErrGoModuleCacheExpired
		}
	}
	return store.ErrNotFound
}

func goModuleAdvertisementPath(p string) bool {
	return strings.HasPrefix(p, "go-catalog/") || strings.HasPrefix(p, "go-latest/")
}

func goModuleFillFailure(e error) string {
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return "retrieval_cancelled"
	}
	if errors.Is(e, upstream.ErrDestination) || errors.Is(e, upstream.ErrRedirect) || errors.Is(e, upstream.ErrPath) {
		return "upstream_authority_failure"
	}
	if errors.Is(e, errGoModuleChecksumRequired) || errors.Is(e, errGoModuleChecksumPublicationRequired) {
		return "upstream_checksum_required"
	}
	if errors.Is(e, crypt.ErrGoChecksumFork) {
		return "upstream_checksum_fork"
	}
	if errors.Is(e, crypt.ErrGoChecksumAuthority) {
		return "upstream_checksum_unverified"
	}
	if errors.Is(e, store.ErrGoChecksumCheckpointChanged) {
		return "upstream_checksum_checkpoint_changed"
	}
	if errors.Is(e, errGoModuleOriginTransient) {
		return "transient_upstream_failure"
	}
	var operation *net.OpError
	if errors.As(e, &operation) && (errors.Is(e, syscall.ECONNREFUSED) || errors.Is(e, syscall.ECONNRESET) || operation.Timeout()) {
		return "transient_upstream_failure"
	}
	return "upstream_go_module_validation_failure"
}

// fillProxy owns slots and renewable lease lifetime. The fetchers only return a
// complete staged bundle/catalog; all authority, lease and publication effects
// remain in the common CompleteRetrieval transaction. No public mode is enabled.
func (s *Server) fillGoModuleProxy(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	// One deadline covers bundle transfer, proof collection, bounded offline
	// checkpoint conflict recovery and publication under the common live lease.
	parent, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	var result store.RetrievalResult
	var e error
	if strings.HasPrefix(lease.Path, "go-latest/") {
		result, e = s.fetchGoModuleLatest(parent, i, repo, lease)
	} else if strings.HasPrefix(lease.Path, "go-catalog/") {
		result, e = s.fetchGoModuleCatalog(parent, i, repo, lease)
	} else {
		result, e = s.fetchGoModuleBundle(parent, i, repo, lease)
	}
	if e != nil {
		result = store.RetrievalResult{Failure: goModuleFillFailure(e)}
		var origin *goModuleOriginStatus
		if errors.As(e, &origin) {
			result.Status = origin.status
		}
		if errors.Is(e, errGoModuleOriginMissing) {
			if origin == nil {
				return store.ErrGoModuleUnvalidated
			}
			result = store.RetrievalResult{Status: 404, FreshSeconds: origin.fresh}
		}
	}
	if parent.Err() != nil {
		result = store.RetrievalResult{Failure: "retrieval_cancelled"}
	}
	ctx := parent
	if parent.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer cancel()
	}
	for attempt := 0; attempt < 2; attempt++ {
		e = s.DB.CompleteRetrieval(ctx, i, lease, result)
		if !errors.Is(e, store.ErrGoChecksumCheckpointChanged) || attempt != 0 || result.GoModule == nil || result.GoModule.Checksum == nil || parent.Err() != nil {
			break
		}
		// A winner may need tiles not present in the immutable first proof.
		// Recollect only proof, once, outside SQL; never re-fetch package bytes
		// or reset the retained timeline. Completion rechecks every lease fence.
		request, err := gomodule.ParseRequest(lease.Path)
		if err != nil {
			e = store.ErrGoModuleUnvalidated
			break
		}
		checkpoint, err := s.DB.GoModuleChecksumCheckpoint(parent, i, repo.Name, repo.SourceRevision)
		if err != nil {
			e = err
			break
		}
		previous := result.GoModule.Checksum
		proof, err := s.fetchGoModuleChecksumProof(parent, i, repo, request.Coordinate, previous.ZIPHash, previous.ModHash, checkpoint.Checkpoint)
		if err != nil {
			e = err
			break
		}
		result.GoModule.Checksum = &store.GoModuleChecksumPublication{Proof: proof.Proof, Object: proof.Object, ZIPHash: previous.ZIPHash, ModHash: previous.ModHash, ExpectedCheckpointRevision: checkpoint.Revision}
	}
	if e != nil && !errors.Is(e, store.ErrQueueFull) && !errors.Is(e, store.ErrHeld) {
		// The common store already retires queue-blocked and held attempts.
		// Other publication failures may still own a lease after rollback.
		// Retire that current lease without granting stale use.
		// Source/grant/lease fences apply to cleanup as well; when they reject
		// it, the existing bounded lease expires without a publication.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer cancel()
		failure := "retrieval_commit_rejected"
		if errors.Is(e, crypt.ErrGoChecksumAuthority) || errors.Is(e, store.ErrGoChecksumCheckpointChanged) {
			failure = goModuleFillFailure(e)
		}
		_ = s.DB.CompleteRetrieval(cleanup, i, lease, store.RetrievalResult{Failure: failure})
	}
	return e
}
