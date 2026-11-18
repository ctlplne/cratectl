// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxExpandedBytes = 256 << 20
	maxFiles         = 10000
)

type Coordinate struct {
	Name    string
	Version string
}

// ReadPublish reads the metadata and lengths in Cargo's little-endian frame.
// The caller stages exactly the returned archive length, then requires EOF.
func ReadPublish(r io.Reader) (Coordinate, int64, error) {
	var length uint32
	if binary.Read(r, binary.LittleEndian, &length) != nil || length == 0 {
		return Coordinate{}, 0, ErrInput
	}
	if length > MaxMetadataBytes {
		return Coordinate{}, 0, ErrLimit
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil || !utf8.Valid(data) {
		return Coordinate{}, 0, ErrInput
	}
	c, err := publishCoordinate(data)
	if err != nil {
		return Coordinate{}, 0, err
	}
	if binary.Read(r, binary.LittleEndian, &length) != nil || length == 0 {
		return Coordinate{}, 0, ErrInput
	}
	if length > MaxUploadBytes {
		return Coordinate{}, 0, ErrLimit
	}
	return c, int64(length), nil
}

func publishCoordinate(data []byte) (Coordinate, error) {
	var c Coordinate
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return c, ErrInput
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(key) > 128 || seen[key] || len(seen) == 128 {
			return c, ErrInput
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return c, ErrInput
		}
		switch key {
		case "name":
			err = json.Unmarshal(value, &c.Name)
		case "vers":
			err = json.Unmarshal(value, &c.Version)
		}
		if err != nil {
			return c, ErrInput
		}
	}
	if _, err := d.Token(); err != nil {
		return c, ErrInput
	}
	if _, err := d.Token(); err != io.EOF {
		return c, ErrInput
	}
	_, err := ArtifactPath(c.Name, c.Version)
	return c, err
}

type archiveReader struct {
	ctx context.Context
	r   io.Reader
}

func (r archiveReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// ReadArchive inspects the normalized Cargo.toml in the staged archive. Package
// source is never written to an extraction directory.
func ReadArchive(ctx context.Context, archive io.Reader, c Coordinate, sparseIndex string) (Entry, error) {
	if _, err := ArtifactPath(c.Name, c.Version); err != nil {
		return Entry{}, err
	}
	compressed := bufio.NewReader(archiveReader{ctx, archive})
	z, err := gzip.NewReader(compressed)
	if err != nil {
		return Entry{}, ErrInput
	}
	defer z.Close()
	z.Multistream(false)
	expanded := &io.LimitedReader{R: z, N: maxExpandedBytes + 1}
	root := c.Name + "-" + c.Version
	seen := make(map[string]bool)
	var manifest []byte
	files := tar.NewReader(expanded)
	for {
		h, err := files.Next()
		if expanded.N == 0 {
			return Entry{}, ErrLimit
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Entry{}, ErrInput
		}
		if len(seen) >= maxFiles || h.Size >= expanded.N {
			return Entry{}, ErrLimit
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if !safeMember(name, root, h.Typeflag) || seen[name] {
			return Entry{}, ErrInput
		}
		seen[name] = true
		if name == root+"/Cargo.toml" {
			if h.Typeflag != tar.TypeReg || h.Size <= 0 {
				return Entry{}, ErrInput
			}
			if h.Size > MaxMetadataBytes {
				return Entry{}, ErrLimit
			}
			manifest = make([]byte, h.Size)
			if _, err := io.ReadFull(files, manifest); err != nil {
				return Entry{}, ErrInput
			}
		}
	}
	// Finish reading the gzip member to verify its checksum. Only normal zero
	// tar padding may follow the end marker, and a second gzip member is refused.
	var padding [4096]byte
	for {
		n, err := expanded.Read(padding[:])
		if expanded.N == 0 {
			return Entry{}, ErrLimit
		}
		if len(bytes.Trim(padding[:n], "\x00")) != 0 || (err != nil && err != io.EOF) {
			return Entry{}, ErrInput
		}
		if err == io.EOF {
			break
		}
	}
	if _, err := compressed.Peek(1); err != io.EOF || manifest == nil {
		return Entry{}, ErrInput
	}
	return parseManifest(manifest, c, sparseIndex)
}

func safeMember(name, root string, kind byte) bool {
	return (kind == tar.TypeDir || kind == tar.TypeReg) &&
		(name == root && kind == tar.TypeDir || strings.HasPrefix(name, root+"/")) &&
		len(name) <= 2048 && utf8.ValidString(name) && path.Clean(name) == name &&
		!strings.ContainsAny(name, ":\\") && strings.IndexFunc(name, unicode.IsControl) < 0
}
