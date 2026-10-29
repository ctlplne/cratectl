// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

// CheckStored observes integrity only. It neither approves content nor grants
// serving access. The expected size, job ceiling and fixed buffer bound I/O.
func (s *Local) CheckStored(ctx context.Context, tenant, digest string, size, maxBytes, bytesPerSecond int64) (string, error) {
	if size < 0 || maxBytes < 1 || size > maxBytes || size >= 1<<62 || bytesPerSecond < 0 {
		return "limit", nil
	}
	f, e := s.Open(tenant, digest)
	if errors.Is(e, os.ErrNotExist) {
		return "missing", nil
	}
	if e != nil {
		return "io_error", nil
	}
	defer f.Close()

	return checkStoredFile(ctx, f, digest, size, maxBytes, bytesPerSecond)
}
func checkStoredFile(ctx context.Context, f *os.File, digest string, size, maxBytes, bytesPerSecond int64) (string, error) {
	if size < 0 || maxBytes < 1 || size > maxBytes || size >= 1<<62 || bytesPerSecond < 0 {
		return "limit", nil
	}
	var reader io.Reader = contextReader{ctx, io.LimitReader(f, size+1)}
	if bytesPerSecond > 0 {
		reader = &pacedReader{ctx: ctx, reader: reader, rate: bytesPerSecond, next: time.Now()}
	}
	h := crypt.SHA256()
	n, e := io.CopyBuffer(h, reader, make([]byte, 64<<10))
	if ctx.Err() != nil {
		return "timeout", ctx.Err()
	}
	if e != nil {
		return "io_error", nil
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return "corrupt", nil
	}
	return "verified", nil
}

type pacedReader struct {
	ctx    context.Context
	reader io.Reader
	rate   int64
	next   time.Time
}

func (r *pacedReader) Read(p []byte) (int, error) {
	n, e := r.reader.Read(p)
	if n > 0 {
		delay := time.Duration(int64(n)/r.rate)*time.Second + time.Duration((int64(n)%r.rate)*int64(time.Second)/r.rate)
		r.next = r.next.Add(delay)
		if wait := time.Until(r.next); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			case <-timer.C:
			}
		}
	}
	return n, e
}
