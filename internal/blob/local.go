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
	if max <= 0 || max >= 1<<62 {
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
	_, e := s.path(tenant, digest)
	if e != nil {
		return nil, e
	}
	return s.openRegularFile(tenant, "sha256", digest[:2], digest)
}

// OpenVerified checks the durable bytes before making a response visible. The
// fixed read buffer bounds memory; the initial implementation trades extra disk
// reads for immediate corruption detection. Performance remains unqualified.
func (s *Local) OpenVerified(ctx context.Context, tenant, digest string, size int64) (*os.File, error) {
	if size < 0 || size >= 1<<62 {
		return nil, ErrIntegrity
	}
	f, err := s.Open(tenant, digest)
	if err != nil {
		return nil, err
	}
	h := crypt.SHA256()
	n, err := io.CopyBuffer(h, io.LimitReader(contextReader{ctx, f}, size+1), make([]byte, 64<<10))
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
	base, e := os.OpenRoot(s.root)
	if e != nil {
		return Object{}, e
	}
	defer base.Close()
	ns, _, e := createCheckedDirectory(base, tenant)
	if e != nil {
		return Object{}, e
	}
	defer ns.Close()
	rootID, e := storageRootIdentity(base, ns, tenant)
	if e != nil {
		return Object{}, e
	}
	stage, _, e := createCheckedDirectory(ns, "staged")
	if e != nil {
		return Object{}, e
	}
	defer stage.Close()
	token, e := crypt.Token()
	if e != nil {
		return Object{}, e
	}
	name := "upload-" + token
	f, e := stage.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return Object{}, e
	}
	defer stage.Remove(name)
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
	stagedInfo, e := f.Stat()
	if e != nil {
		return Object{}, e
	}
	sha, _, e := createCheckedDirectory(ns, "sha256")
	if e != nil {
		return Object{}, e
	}
	defer sha.Close()
	prefix, _, e := createCheckedDirectory(sha, digest[:2])
	if e != nil {
		return Object{}, e
	}
	defer prefix.Close()
	if e = ns.Link("staged/"+name, "sha256/"+digest[:2]+"/"+digest); e != nil {
		if !errors.Is(e, os.ErrExist) {
			return Object{}, e
		}
		existing, e := s.Open(tenant, digest)
		if e != nil {
			return Object{}, e
		}
		defer existing.Close()
		check := crypt.SHA256()
		size, e := io.CopyBuffer(check, io.LimitReader(contextReader{ctx, existing}, n+1), make([]byte, 64<<10))
		if e != nil || size != n || hex.EncodeToString(check.Sum(nil)) != digest {
			return Object{}, fmt.Errorf("%w: existing object", ErrIntegrity)
		}
	} else {
		// A descriptor comparison also detects replacement of the staging name.
		linked, e := prefix.Lstat(digest)
		if e != nil || !linked.Mode().IsRegular() || !os.SameFile(stagedInfo, linked) {
			return Object{}, ErrStorageChanged
		}
	}
	for _, dir := range []*os.Root{prefix, sha, stage, ns, base} {
		if e = syncRoot(dir); e != nil {
			return Object{}, e
		}
	}
	if e = f.Close(); e != nil {
		return Object{}, e
	}
	current, e := s.InventoryRoot(tenant)
	if e != nil {
		return Object{}, e
	}
	if current != rootID {
		return Object{}, ErrStorageChanged
	}
	// Recheck the directory layout before references can become visible.
	visible, e := s.Open(tenant, digest)
	if e != nil {
		return Object{}, e
	}
	visible.Close()
	if e = ctx.Err(); e != nil {
		return Object{}, e
	}
	return Object{Digest: digest, Size: n}, nil
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
	f, e := s.openRegularFile(tenant, "uploads", id)
	if e != nil {
		return Object{}, e
	}
	defer f.Close()
	return s.Put(ctx, tenant, f, digest, size)
}
