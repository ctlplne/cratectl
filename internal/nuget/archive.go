// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	cryptox "ctlplne.dev/cratectl/internal/crypto"
)

var ErrArchive = errors.New("invalid, ambiguous, unsupported or oversized NuGet archive")

// ArchiveLimits are admission budgets, not package or edition entitlements.
// ZIP64 and split archives require a separate implementation and qualification.
type ArchiveLimits struct {
	CompressedBytes int64
	ExpandedBytes   int64
	DirectoryBytes  int64
	Files           int
}

type ArchiveIdentity struct {
	Identity      NuspecIdentity
	NuspecPath    string
	Nuspec        []byte
	Files         int
	ExpandedBytes int64
}

type archiveEntry struct {
	name                string
	offset, crc, packed uint32
	expanded            uint32
	flags, method       uint16
}

type archiveReader struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r archiveReader) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(p, offset)
}

// archiveFold is a conservative Unicode simple-fold collision key. It is
// never the package ID key, a path rewrite, or a filesystem extraction target.
func archiveFold(name string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		return least
	}, norm.NFC.String(name))
}

func archivePath(name string) bool {
	if len(name) > 2048 || !utf8.ValidString(name) || strings.ContainsAny(name, `\:%<>"|?*`) || strings.ContainsFunc(name, func(r rune) bool { return r < 32 || r == 127 }) {
		return false
	}
	name = strings.TrimSuffix(name, "/")
	if name == "" || name == "." || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 64 {
		return false
	}
	for _, part := range parts {
		if part == ".." || strings.TrimRight(part, " .") != part {
			return false
		}
		device := strings.ToUpper(strings.TrimRight(strings.SplitN(part, ".", 2)[0], " "))
		if device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" || device == "CONIN$" || device == "CONOUT$" {
			return false
		}
		if strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT") {
			suffix := device[3:]
			if (len(suffix) == 1 && suffix[0] >= '1' && suffix[0] <= '9') || suffix == "¹" || suffix == "²" || suffix == "³" {
				return false
			}
		}
	}
	return true
}

func archiveExtra(extra []byte) bool {
	for len(extra) > 0 {
		if len(extra) < 4 {
			return false
		}
		tag, length := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		if length > len(extra)-4 || tag == 0x0001 || tag == 0x7075 || tag == 0x000d {
			return false // ZIP64, an alternate Unicode path, or a Unix link record.
		}
		extra = extra[4+length:]
	}
	return true
}

// archiveDirectory bounds physical central-directory entries before zip.NewReader
// can allocate them. EOCD's claimed count alone is not an allocation bound.
func archiveDirectory(ctx context.Context, r io.ReaderAt, size int64, limits ArchiveLimits) ([]archiveEntry, int64, error) {
	tail := make([]byte, min(size, int64(65535+22)))
	if _, err := r.ReadAt(tail, size-int64(len(tail))); err != nil {
		return nil, 0, ErrArchive
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if bytes.Equal(tail[i:i+4], []byte{'P', 'K', 5, 6}) && int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail)-i-22 {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, 0, ErrArchive
	}
	eocd := tail[end:]
	count := int(binary.LittleEndian.Uint16(eocd[10:]))
	length, offset := int64(binary.LittleEndian.Uint32(eocd[12:])), int64(binary.LittleEndian.Uint32(eocd[16:]))
	if binary.LittleEndian.Uint16(eocd[4:]) != 0 || binary.LittleEndian.Uint16(eocd[6:]) != 0 || int(binary.LittleEndian.Uint16(eocd[8:])) != count || count == 0 || count == 65535 || count > limits.Files || length <= 0 || length > limits.DirectoryBytes || offset <= 0 || offset+length != size-int64(len(tail))+int64(end) {
		return nil, 0, ErrArchive
	}
	directory := make([]byte, length)
	if _, err := r.ReadAt(directory, offset); err != nil {
		return nil, 0, ErrArchive
	}
	entries := make([]archiveEntry, 0, count)
	for len(directory) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if len(entries) >= count || len(directory) < 46 || !bytes.Equal(directory[:4], []byte{'P', 'K', 1, 2}) {
			return nil, 0, ErrArchive
		}
		h := directory
		nameBytes, extraBytes, commentBytes := int(binary.LittleEndian.Uint16(h[28:])), int(binary.LittleEndian.Uint16(h[30:])), int(binary.LittleEndian.Uint16(h[32:]))
		next := 46 + nameBytes + extraBytes + commentBytes
		if next > len(h) || nameBytes > 2048 || binary.LittleEndian.Uint16(h[34:]) != 0 || !archiveExtra(h[46+nameBytes:46+nameBytes+extraBytes]) {
			return nil, 0, ErrArchive
		}
		entry := archiveEntry{name: string(h[46 : 46+nameBytes]), flags: binary.LittleEndian.Uint16(h[8:]), method: binary.LittleEndian.Uint16(h[10:]), crc: binary.LittleEndian.Uint32(h[16:]), packed: binary.LittleEndian.Uint32(h[20:]), expanded: binary.LittleEndian.Uint32(h[24:]), offset: binary.LittleEndian.Uint32(h[42:])}
		if !archivePath(entry.name) || entry.flags & ^uint16(0x080e) != 0 || (entry.method != zip.Store && entry.method != zip.Deflate) || entry.packed == 0xffffffff || entry.expanded == 0xffffffff || int64(entry.offset) >= offset || (strings.ContainsFunc(entry.name, func(r rune) bool { return r > 127 }) && entry.flags&0x800 == 0) {
			return nil, 0, ErrArchive
		}
		entries = append(entries, entry)
		directory = directory[next:]
	}
	if len(entries) != count {
		return nil, 0, ErrArchive
	}
	return entries, offset, nil
}

func archiveLocalHeaders(ctx context.Context, r io.ReaderAt, entries []archiveEntry, directory int64) error {
	ordered := append([]archiveEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].offset < ordered[j].offset })
	var position int64
	for index, entry := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(entry.offset) != position || directory-position < 30 {
			return ErrArchive
		}
		var header [30]byte
		if _, err := r.ReadAt(header[:], position); err != nil {
			return ErrArchive
		}
		h := header[:]
		nameBytes, extraBytes := int64(binary.LittleEndian.Uint16(h[26:])), int64(binary.LittleEndian.Uint16(h[28:]))
		data := position + 30 + nameBytes + extraBytes
		if !bytes.Equal(h[:4], []byte{'P', 'K', 3, 4}) || binary.LittleEndian.Uint16(h[6:]) != entry.flags || binary.LittleEndian.Uint16(h[8:]) != entry.method || data > directory || nameBytes != int64(len(entry.name)) {
			return ErrArchive
		}
		variable := make([]byte, nameBytes+extraBytes)
		if _, err := r.ReadAt(variable, position+30); err != nil || string(variable[:nameBytes]) != entry.name || !archiveExtra(variable[nameBytes:]) {
			return ErrArchive
		}
		localCRC, localPacked, localExpanded := binary.LittleEndian.Uint32(h[14:]), binary.LittleEndian.Uint32(h[18:]), binary.LittleEndian.Uint32(h[22:])
		if entry.flags&8 == 0 {
			if localCRC != entry.crc || localPacked != entry.packed || localExpanded != entry.expanded {
				return ErrArchive
			}
		} else if (localCRC != 0 && localCRC != entry.crc) || (localPacked != 0 && localPacked != entry.packed) || (localExpanded != 0 && localExpanded != entry.expanded) {
			return ErrArchive
		}
		position = data + int64(entry.packed)
		if position > directory {
			return ErrArchive
		}
		if entry.flags&8 != 0 {
			var descriptor [16]byte
			next := directory
			if index+1 < len(ordered) {
				next = int64(ordered[index+1].offset)
			}
			length := next - position
			if length != 12 && length != 16 {
				return ErrArchive
			}
			if _, err := r.ReadAt(descriptor[:length], position); err != nil {
				return ErrArchive
			}
			d := descriptor[:12]
			if length == 16 {
				if !bytes.Equal(descriptor[:4], []byte{'P', 'K', 7, 8}) {
					return ErrArchive
				}
				d = descriptor[4:]
			}
			if binary.LittleEndian.Uint32(d) != entry.crc || binary.LittleEndian.Uint32(d[4:]) != entry.packed || binary.LittleEndian.Uint32(d[8:]) != entry.expanded {
				return ErrArchive
			}
			position += length
		}
	}
	if position != directory {
		return ErrArchive
	}
	return nil
}

// Implement flate.Reader so the decompressor cannot hide trailing compressed
// bytes through read-ahead. Count bytes consumed from the buffered view, not
// the larger prefetches made by its underlying ReaderAt.
type archivePackedReader struct {
	r        *bufio.Reader
	consumed int64
}

func (r *archivePackedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.consumed += int64(n)
	return n, err
}
func (r *archivePackedReader) ReadByte() (byte, error) {
	b, err := r.r.ReadByte()
	if err == nil {
		r.consumed++
	}
	return b, err
}

// InspectArchive inspects one immutable ReaderAt view. The caller must retain
// that exact staged byte object and bind its digest through the common store
// transaction; this result alone neither publishes nor approves a package.
// Files are never extracted, loaded, built or executed. Only Nuspec is buffered.
func InspectArchive(ctx context.Context, input io.ReaderAt, size int64, limits ArchiveLimits) (out ArchiveIdentity, err error) {
	defer func() {
		if ctx.Err() != nil {
			out, err = ArchiveIdentity{}, ctx.Err()
		}
	}()
	if err = ctx.Err(); err != nil {
		return ArchiveIdentity{}, err
	}
	if input == nil || size < 22 || size >= 1<<32 || limits.CompressedBytes <= 0 || size > limits.CompressedBytes || limits.ExpandedBytes <= 0 || limits.ExpandedBytes > 1<<40 || limits.DirectoryBytes <= 0 || limits.DirectoryBytes > 16<<20 || limits.Files <= 0 || limits.Files > 16384 {
		return ArchiveIdentity{}, ErrArchive
	}
	r := archiveReader{ctx: ctx, r: input}
	entries, directory, err := archiveDirectory(ctx, r, size, limits)
	if err != nil {
		return ArchiveIdentity{}, err
	}
	if err = archiveLocalHeaders(ctx, r, entries, directory); err != nil {
		return ArchiveIdentity{}, err
	}
	z, err := zip.NewReader(r, size)
	if err != nil || len(z.File) != len(entries) {
		return ArchiveIdentity{}, ErrArchive
	}
	types := make(map[string]bool, len(entries))
	var expanded int64
	manifestIndex := -1
	for index, file := range z.File {
		if err := ctx.Err(); err != nil {
			return ArchiveIdentity{}, err
		}
		entry := entries[index]
		if file.Name != entry.name || file.Flags != entry.flags || file.Method != entry.method || file.CompressedSize64 != uint64(entry.packed) || file.UncompressedSize64 != uint64(entry.expanded) || file.CRC32 != entry.crc || (!file.Mode().IsRegular() && !file.Mode().IsDir()) {
			return ArchiveIdentity{}, ErrArchive
		}
		name := archiveFold(strings.TrimSuffix(file.Name, "/"))
		if _, exists := types[name]; exists {
			return ArchiveIdentity{}, ErrArchive
		}
		types[name] = file.Mode().IsDir()
		if int64(entry.expanded) > limits.ExpandedBytes-expanded {
			return ArchiveIdentity{}, ErrArchive
		}
		expanded += int64(entry.expanded)
		if file.Mode().IsDir() && (entry.expanded != 0 || entry.packed != 0) {
			return ArchiveIdentity{}, ErrArchive
		}
		extension := path.Ext(file.Name)
		if path.Dir(file.Name) == "." && len(extension) == len(".nuspec") && strings.EqualFold(extension, ".nuspec") {
			if manifestIndex != -1 || !file.Mode().IsRegular() || entry.expanded > MaxNuspecBytes {
				return ArchiveIdentity{}, ErrArchive
			}
			manifestIndex = index
		}
	}
	if manifestIndex < 0 {
		return ArchiveIdentity{}, ErrArchive
	}
	for name := range types {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if isDir, exists := types[parent]; exists && !isDir {
				return ArchiveIdentity{}, ErrArchive
			}
		}
	}
	var manifest []byte
	buffer := make([]byte, 32<<10)
	for index, file := range z.File {
		raw, err := file.OpenRaw()
		if err != nil {
			return ArchiveIdentity{}, ErrArchive
		}
		packed := &archivePackedReader{r: bufio.NewReaderSize(raw, 32<<10)}
		var stream io.ReadCloser = io.NopCloser(packed)
		if file.Method == zip.Deflate {
			stream = flate.NewReader(packed)
		}
		checksum := cryptox.ZIPCRC32()
		var written int64
		for {
			if err := ctx.Err(); err != nil {
				stream.Close()
				return ArchiveIdentity{}, err
			}
			n, readErr := stream.Read(buffer)
			written += int64(n)
			if written > int64(entries[index].expanded) {
				stream.Close()
				return ArchiveIdentity{}, ErrArchive
			}
			checksum.Write(buffer[:n])
			if index == manifestIndex {
				manifest = append(manifest, buffer[:n]...)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || n == 0 {
				stream.Close()
				return ArchiveIdentity{}, ErrArchive
			}
		}
		closeErr := stream.Close()
		if closeErr != nil || written != int64(entries[index].expanded) || checksum.Sum32() != entries[index].crc || packed.consumed != int64(entries[index].packed) {
			return ArchiveIdentity{}, ErrArchive
		}
	}
	identity, err := ParseNuspecIdentity(ctx, manifest)
	if err != nil {
		return ArchiveIdentity{}, ErrArchive
	}
	return ArchiveIdentity{Identity: identity, NuspecPath: entries[manifestIndex].name, Nuspec: manifest, Files: len(entries), ExpandedBytes: expanded}, nil
}
