// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/hex"
	"hash"
	"io"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (s *Server) publishMavenSnapshot(ctx context.Context, i store.Identity, repo string, a store.Artifact) error {
	// Blob.Put already synced the immutable bytes. Read their verified identity
	// once with bounded memory to bind delayed native sidecars to this publisher.
	file, e := s.Blobs.OpenVerified(ctx, i.Tenant, a.Digest, a.Size)
	if e != nil {
		return e
	}
	hashes := map[string]hash.Hash{}
	writers := []io.Writer{}
	for _, name := range []string{"sha256", "sha512", "sha384", "sha1", "md5"} {
		h := crypt.CompatibilityHash(name)
		hashes[name] = h
		writers = append(writers, h)
	}
	_, e = io.Copy(io.MultiWriter(writers...), file)
	closeError := file.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	sums := map[string]string{}
	for name, h := range hashes {
		sums[name] = hex.EncodeToString(h.Sum(nil))
	}
	return s.DB.PublishMavenSnapshot(ctx, i, repo, a, sums)
}
