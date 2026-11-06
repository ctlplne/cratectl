// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/dirhash"
)

var ErrGoChecksum = errors.New("invalid, incomplete or oversized Go checksum input")

// GoDirectoryHash computes Go's h1 directory checksum while the bounded archive
// inspector streams entries. It retains names and digests, never file contents.
// It is local to one inspection and is not safe for concurrent use. A checksum
// identifies contents; it does not establish an independent trust authority.
type GoDirectoryHash struct {
	files              map[string]*goChecksumFile
	maxFiles           int
	remainingNameBytes int64
	failed, sealed     bool
	result             string
}

type goChecksumFile struct {
	owner     *GoDirectoryHash
	hash      hash.Hash
	remaining int64
}

func NewGoDirectoryHash(maxFiles int, nameBytes int64) (*GoDirectoryHash, error) {
	if maxFiles < 1 || maxFiles > 65534 || nameBytes < 1 || nameBytes > 128<<20 {
		return nil, ErrGoChecksum
	}
	return &GoDirectoryHash{files: map[string]*goChecksumFile{}, maxFiles: maxFiles, remainingNameBytes: nameBytes}, nil
}

// File admits one exact ZIP entry name, including explicit directory entries.
// Names are neither cleaned nor unescaped: Go hashes the original ZIP names.
// The caller must separately validate module identity and archive structure.
func (h *GoDirectoryHash) File(name string, size int64) (io.Writer, error) {
	if h == nil || h.failed || h.sealed {
		return nil, ErrGoChecksum
	}
	if name == "" || len(name) > 2048 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) || size < 0 || len(h.files) >= h.maxFiles || int64(len(name)) > h.remainingNameBytes || h.files[name] != nil {
		h.failed = true
		return nil, ErrGoChecksum
	}
	f := &goChecksumFile{owner: h, hash: SHA256(), remaining: size}
	h.files[name] = f
	h.remainingNameBytes -= int64(len(name))
	return f, nil
}

func (f *goChecksumFile) Write(data []byte) (int, error) {
	if f.owner.failed || f.owner.sealed || int64(len(data)) > f.remaining {
		f.owner.failed = true
		return 0, ErrGoChecksum
	}
	f.remaining -= int64(len(data))
	return f.hash.Write(data)
}

// Sum seals the inventory only after every admitted byte has been supplied.
// Discard the result if any surrounding archive or module validation fails.
func (h *GoDirectoryHash) Sum() (string, error) {
	if h == nil || h.failed {
		return "", ErrGoChecksum
	}
	if h.sealed {
		return h.result, nil
	}
	files := make([]string, 0, len(h.files))
	for name, f := range h.files {
		if f.remaining != 0 {
			h.failed = true
			return "", ErrGoChecksum
		}
		files = append(files, name)
	}
	sort.Strings(files)
	summary := SHA256()
	for _, name := range files {
		fmt.Fprintf(summary, "%x  %s\n", h.files[name].hash.Sum(nil), name)
	}
	h.result = "h1:" + base64.StdEncoding.EncodeToString(summary.Sum(nil))
	h.sealed = true
	return h.result, nil
}

// GoModHash uses the standard Go go.sum algorithm on the original go.mod bytes.
// Module syntax and size limits belong to the caller's admission path.
func GoModHash(data []byte) (string, error) {
	return dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}
