// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"regexp"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

var uploadID = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// StageUpload stores one immutable chunk. A stale operation can leave unreferenced
// bytes, but cannot truncate another operation's bytes or advance its offset.
func (s *Local) StageUpload(ctx context.Context, tenant string, offset int64, r io.Reader, length int64) (Object, error) {
	if offset < 0 || offset > s.max {
		return Object{}, ErrLimit
	}
	if length > s.max-offset {
		return Object{}, ErrLimit
	}
	bounded := *s
	bounded.max = s.max - offset
	return bounded.Put(ctx, tenant, r, "", length)
}

// ImportUploadPrefix reads only bytes acknowledged by the old upload protocol.
// The legacy file and any unacknowledged tail are retained unchanged.
func (s *Local) ImportUploadPrefix(ctx context.Context, tenant, id string, size int64) (Object, error) {
	if !namespace.MatchString(tenant) || !uploadID.MatchString(id) || size <= 0 || size > s.max {
		return Object{}, ErrLength
	}
	f, e := s.openRegularFile(tenant, "uploads", id)
	if e != nil {
		return Object{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return Object{}, e
	}
	if info.Size() < size {
		return Object{}, ErrLength
	}
	return s.Put(ctx, tenant, io.LimitReader(f, size), "", size)
}

// AssembleUpload checks every part while streaming into a new immutable object.
// Only one part file and a fixed copy buffer are open at a time.
func (s *Local) AssembleUpload(ctx context.Context, tenant string, parts []Object, digest string) (Object, error) {
	var size int64
	for _, p := range parts {
		if p.Size <= 0 || p.Size > s.max-size {
			return Object{}, ErrLimit
		}
		size += p.Size
	}
	r := &uploadReader{store: s, tenant: tenant, ctx: ctx, parts: parts}
	defer r.Close()
	return s.Put(ctx, tenant, r, digest, size)
}

type uploadReader struct {
	store  *Local
	tenant string
	ctx    context.Context
	parts  []Object
	f      *os.File
	h      hash.Hash
	read   int64
}

func (r *uploadReader) Close() error {
	if r.f != nil {
		e := r.f.Close()
		r.f = nil
		return e
	}
	return nil
}
func (r *uploadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if e := r.ctx.Err(); e != nil {
			return 0, e
		}
		if len(r.parts) == 0 {
			return 0, io.EOF
		}
		part := r.parts[0]
		if r.f == nil {
			f, e := r.store.Open(r.tenant, part.Digest)
			if e != nil {
				return 0, e
			}
			r.f = f
			r.h = crypt.SHA256()
			r.read = 0
		}
		// Read at most one byte beyond the declared part, including on damaged disks.
		bounded := p
		if remaining := part.Size - r.read + 1; int64(len(bounded)) > remaining {
			bounded = bounded[:int(remaining)]
		}
		n, e := r.f.Read(bounded)
		r.read += int64(n)
		r.h.Write(bounded[:n])
		if r.read > part.Size {
			return n, ErrIntegrity
		}
		if e == io.EOF {
			if r.read != part.Size || hex.EncodeToString(r.h.Sum(nil)) != part.Digest {
				return n, ErrIntegrity
			}
			if e = r.Close(); e != nil {
				return n, e
			}
			r.parts = r.parts[1:]
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, e
	}
}
