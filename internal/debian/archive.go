// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
)

const MaxArchiveBytes int64 = 512 << 20
const maxControlTarBytes = 4 << 20

var ErrArchive = errors.New("invalid or unsupported Debian binary package archive")

// Inspect reads a bounded metadata member from a Debian ar archive. It leaves
// the data tar and any maintainer scripts opaque. Files are never extracted.
func Inspect(ctx context.Context, source io.ReaderAt, size int64) (Control, error) {
	if size < 8 || size > MaxArchiveBytes {
		return Control{}, ErrArchive
	}
	var magic [8]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "!<arch>\n" {
		return Control{}, ErrArchive
	}
	var control Control
	section, members := 0, 0
	for offset := int64(8); offset < size; {
		if err := ctx.Err(); err != nil {
			return Control{}, err
		}
		members++
		if members > 16 {
			return Control{}, ErrArchive
		}
		name, data, end, err := arMember(source, offset, size)
		if err != nil {
			return Control{}, err
		}
		offset = end
		if section > 0 && strings.HasPrefix(name, "_") {
			continue
		}
		switch section {
		case 0:
			if name != "debian-binary" || data.Size() != 4 {
				return Control{}, ErrArchive
			}
			var version [4]byte
			if _, err := io.ReadFull(data, version[:]); err != nil || string(version[:]) != "2.0\n" {
				return Control{}, ErrArchive
			}
		case 1:
			if name != "control.tar" && name != "control.tar.gz" {
				return Control{}, ErrArchive
			}
			control, err = inspectControlTar(data, name == "control.tar.gz")
			if err != nil {
				return Control{}, err
			}
		case 2:
			switch name {
			case "data.tar", "data.tar.gz", "data.tar.xz", "data.tar.zst", "data.tar.lzma", "data.tar.bz2":
			default:
				return Control{}, ErrArchive
			}
			if data.Size() == 0 {
				return Control{}, ErrArchive
			}
		default:
			return Control{}, ErrArchive
		}
		section++
	}
	if section != 3 {
		return Control{}, ErrArchive
	}
	return control, nil
}

func arMember(source io.ReaderAt, offset, size int64) (string, *io.SectionReader, int64, error) {
	var header [60]byte
	if size-offset < int64(len(header)) {
		return "", nil, 0, ErrArchive
	}
	if _, err := source.ReadAt(header[:], offset); err != nil || string(header[58:]) != "`\n" {
		return "", nil, 0, ErrArchive
	}
	offset += int64(len(header))
	name := strings.TrimSuffix(strings.TrimRight(string(header[:16]), " "), "/")
	length := strings.TrimRight(string(header[48:58]), " ")
	for _, b := range length {
		if b < '0' || b > '9' {
			return "", nil, 0, ErrArchive
		}
	}
	n, err := strconv.ParseInt(length, 10, 64)
	if err != nil || n > size-offset || name == "" || len(name) > 15 || strings.ContainsAny(name, "/\\\r\n\x00 \t") {
		return "", nil, 0, ErrArchive
	}
	end := offset + n
	if n%2 == 1 {
		var padding [1]byte
		if end >= size {
			return "", nil, 0, ErrArchive
		}
		if _, err := source.ReadAt(padding[:], end); err != nil || padding[0] != '\n' {
			return "", nil, 0, ErrArchive
		}
		end++
	}
	return name, io.NewSectionReader(source, offset, n), end, nil
}

func inspectControlTar(section *io.SectionReader, compressed bool) (Control, error) {
	if section.Size() > maxControlTarBytes {
		return Control{}, ErrArchive
	}
	raw, err := io.ReadAll(section)
	if err != nil {
		return Control{}, ErrArchive
	}
	if compressed {
		input := bytes.NewReader(raw)
		gz, err := gzip.NewReader(input)
		if err != nil {
			return Control{}, ErrArchive
		}
		gz.Multistream(false)
		raw, err = io.ReadAll(io.LimitReader(gz, maxControlTarBytes+1))
		closeErr := gz.Close()
		if err != nil || closeErr != nil || len(raw) > maxControlTarBytes || input.Len() != 0 {
			return Control{}, ErrArchive
		}
	}
	input := bytes.NewReader(raw)
	reader := tar.NewReader(input)
	var control []byte
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(seen) >= 128 {
			return Control{}, ErrArchive
		}
		name := strings.TrimPrefix(header.Name, "./")
		if (name == "" || name == ".") && header.Typeflag == tar.TypeDir && header.Size == 0 {
			continue
		}
		if len(name) > 255 || name == "" || name == "." || name == ".." || seen[name] || strings.ContainsAny(name, "/\\\r\n\x00") ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return Control{}, ErrArchive
		}
		seen[name] = true
		if name == "control" {
			if header.Size < 1 || header.Size > MaxControlBytes {
				return Control{}, ErrControl
			}
			control, err = io.ReadAll(reader)
			if err != nil || int64(len(control)) != header.Size {
				return Control{}, ErrArchive
			}
		}
	}
	for _, b := range raw[len(raw)-input.Len():] {
		if b != 0 {
			return Control{}, ErrArchive
		}
	}
	return ParseControl(control)
}
