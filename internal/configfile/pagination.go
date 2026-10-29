// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// PaginationKey loads or privately creates a shared, durable cursor key. Link
// publishes only complete synced bytes and never replaces a concurrent winner.
func PaginationKey(path string) (*crypt.CursorKey, error) {
	load := func() (*crypt.CursorKey, error) {
		b, e := ReadBytes(path, 128, true)
		if e != nil {
			return nil, e
		}
		defer clear(b)
		return crypt.ParseCursorKey(strings.TrimSpace(string(b)))
	}
	if _, e := os.Lstat(path); e == nil {
		return load()
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	secret, e := crypt.Token()
	if e != nil {
		return nil, e
	}
	parent, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	nonce, e := crypt.Token()
	if e != nil {
		return nil, e
	}
	tmp := ".pagination-" + nonce
	f, e := parent.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer parent.Remove(tmp)
	_, e = f.WriteString(secret + "\n")
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e == nil {
		e = closed
	}
	if e != nil {
		return nil, e
	}
	if e = parent.Link(tmp, filepath.Base(path)); e != nil && !errors.Is(e, os.ErrExist) {
		return nil, e
	}
	directory, e := parent.Open(".")
	if e != nil {
		return nil, e
	}
	e = directory.Sync()
	directory.Close()
	if e != nil {
		return nil, e
	}
	return load()
}
