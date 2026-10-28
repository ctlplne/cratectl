// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

var namespace = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var ErrLimit = errors.New("object exceeds configured upload limit")
var ErrDigest = errors.New("declared digest does not match uploaded bytes")
var ErrLength = errors.New("declared length does not match uploaded bytes")
var ErrIntegrity = errors.New("stored object integrity failure")

type Object struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}
type Local struct {
	root string
	max  int64
}

func New(root string, max int64) (*Local, error) {
	if max <= 0 {
		return nil, errors.New("positive object limit required")
	}
	a, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(a, 0700); e != nil {
		return nil, e
	}
	return &Local{a, max}, nil
}
func (s *Local) path(tenant, digest string) (string, error) {
	if !namespace.MatchString(tenant) || len(digest) != 64 {
		return "", errors.New("invalid object identity")
	}
	if _, e := hex.DecodeString(digest); e != nil {
		return "", e
	}
	return filepath.Join(s.root, tenant, "sha256", digest[:2], digest), nil
}
func (s *Local) Open(tenant, digest string) (*os.File, error) {
	p, e := s.path(tenant, digest)
	if e != nil {
		return nil, e
	}
	return os.Open(p)
}

// OpenVerified checks the durable bytes before making a response visible. The
// fixed read buffer bounds memory; the initial implementation trades extra disk
// reads for immediate corruption detection. Performance remains unqualified.
func (s *Local) OpenVerified(ctx context.Context, tenant, digest string, size int64) (*os.File, error) {
	f, err := s.Open(tenant, digest)
	if err != nil {
		return nil, err
	}
	h := crypt.SHA256()
	n, err := io.CopyBuffer(h, contextReader{ctx, f}, make([]byte, 64<<10))
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		f.Close()
		return nil, ErrIntegrity
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// Put never buffers an entire object. A published reference is only allowed after
// Put returns successfully. Unreferenced objects are retained for reconciliation.
func (s *Local) Put(ctx context.Context, tenant string, r io.Reader, expected string, length int64) (Object, error) {
	if !namespace.MatchString(tenant) {
		return Object{}, errors.New("invalid tenant")
	}
	stage := filepath.Join(s.root, tenant, "staged")
	if e := os.MkdirAll(stage, 0700); e != nil {
		return Object{}, e
	}
	f, e := os.CreateTemp(stage, "upload-")
	if e != nil {
		return Object{}, e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := crypt.SHA256()
	n, e := io.CopyBuffer(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx, r}, s.max+1), make([]byte, 64<<10))
	if e != nil {
		return Object{}, e
	}
	if n > s.max {
		return Object{}, ErrLimit
	}
	if length >= 0 && n != length {
		return Object{}, ErrLength
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if expected != "" && expected != digest {
		return Object{}, ErrDigest
	}
	if e = f.Sync(); e != nil {
		return Object{}, e
	}
	if e = f.Close(); e != nil {
		return Object{}, e
	}
	dest, e := s.path(tenant, digest)
	if e != nil {
		return Object{}, e
	}
	dir := filepath.Dir(dest)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return Object{}, e
	}
	// Ensure newly created namespace directory entries also survive a crash.
	for p := dir; ; p = filepath.Dir(p) {
		if e = syncDir(p); e != nil {
			return Object{}, e
		}
		if p == s.root {
			break
		}
	}
	if e = os.Link(f.Name(), dest); e != nil {
		if !errors.Is(e, os.ErrExist) {
			return Object{}, e
		}
		// A matching filename is not proof of matching bytes after storage damage.
		existing, err := os.Open(dest)
		if err != nil {
			return Object{}, err
		}
		defer existing.Close()
		eh := crypt.SHA256()
		size, err := io.Copy(eh, existing)
		if err != nil || size != n || hex.EncodeToString(eh.Sum(nil)) != digest {
			return Object{}, fmt.Errorf("%w: existing object", ErrIntegrity)
		}
	}
	if e = syncDir(dir); e != nil {
		return Object{}, e
	}
	return Object{digest, n}, nil
}

// AppendUpload reconciles unacknowledged trailing bytes after a crashed chunk
// transaction. The database's committed offset is authoritative.
func (s *Local) AppendUpload(ctx context.Context, tenant, id string, offset int64, r io.Reader) (int64, error) {
	if !namespace.MatchString(tenant) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(id) || offset < 0 || offset > s.max {
		return 0, errors.New("invalid upload identity")
	}
	dir := filepath.Join(s.root, tenant, "uploads")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return 0, e
	}
	p := filepath.Join(dir, id)
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return 0, e
	}
	if st.Size() < offset {
		return 0, errors.New("acknowledged upload bytes missing")
	}
	if e = f.Truncate(offset); e != nil {
		return 0, e
	}
	if _, e = f.Seek(offset, io.SeekStart); e != nil {
		return 0, e
	}
	n, e := io.CopyBuffer(f, io.LimitReader(contextReader{ctx, r}, s.max-offset+1), make([]byte, 64<<10))
	if e != nil || n > s.max-offset {
		f.Truncate(offset)
		if e != nil {
			return 0, e
		}
		return 0, ErrLimit
	}
	if e = f.Sync(); e != nil {
		return 0, e
	}
	if e = syncDir(dir); e != nil {
		return 0, e
	}
	return offset + n, nil
}
func (s *Local) FinishUpload(ctx context.Context, tenant, id, digest string, size int64) (Object, error) {
	if !namespace.MatchString(tenant) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(id) {
		return Object{}, errors.New("invalid upload identity")
	}
	f, e := os.Open(filepath.Join(s.root, tenant, "uploads", id))
	if e != nil {
		return Object{}, e
	}
	defer f.Close()
	return s.Put(ctx, tenant, f, digest, size)
}
