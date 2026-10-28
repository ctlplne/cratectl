// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/textproto"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	pep "github.com/aquasecurity/go-pep440-version"
)

var errPythonArchive = errors.New("invalid or oversized Python distribution archive")
var pythonTag = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)
var pythonBuild = regexp.MustCompile(`^[0-9][A-Za-z0-9_]*$`)

type pythonArchiveBudget struct {
	Expanded int64
	Files    int
	Metadata int64
}
type pythonCore struct{ Name, Version, RequiresPython, Raw string }

func pythonDistribution(filename string) (name, version, kind string, e error) {
	if len(filename) > 255 || path.Base(filename) != filename || !npmArchiveText(filename) {
		return "", "", "", errPythonArchive
	}
	var rawVersion string
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if len(parts) != 5 && len(parts) != 6 {
			return "", "", "", errPythonArchive
		}
		if len(parts) == 6 && !pythonBuild.MatchString(parts[2]) {
			return "", "", "", errPythonArchive
		}
		for _, tag := range parts[len(parts)-3:] {
			if !pythonTag.MatchString(tag) {
				return "", "", "", errPythonArchive
			}
		}
		name, rawVersion, kind = parts[0], parts[1], "wheel"
	} else {
		stem := ""
		if strings.HasSuffix(filename, ".tar.gz") {
			stem = strings.TrimSuffix(filename, ".tar.gz")
			kind = "tar"
		} else if strings.HasSuffix(filename, ".zip") {
			stem = strings.TrimSuffix(filename, ".zip")
			kind = "zip"
		} else {
			return "", "", "", errPythonArchive
		}
		cut := strings.LastIndex(stem, "-")
		if cut <= 0 {
			return "", "", "", errPythonArchive
		}
		name, rawVersion = stem[:cut], stem[cut+1:]
	}
	name = NormalizePython(name)
	if !pyName.MatchString(name) || len(name) > 200 || len(rawVersion) > 100 {
		return "", "", "", errPythonArchive
	}
	v, e := pep.Parse(rawVersion)
	if e != nil {
		return "", "", "", errPythonArchive
	}
	return name, v.String(), kind, nil
}
func pythonCoreMetadata(raw []byte, name, version string) (pythonCore, error) {
	var out pythonCore
	if !utf8.Valid(raw) {
		return out, errPythonArchive
	}
	headers, e := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if e != nil || len(headers.Values("Name")) != 1 || len(headers.Values("Version")) != 1 || len(headers.Values("Metadata-Version")) != 1 || len(headers.Values("Requires-Python")) > 1 {
		return out, errPythonArchive
	}
	metadataVersion := strings.Split(headers.Get("Metadata-Version"), ".")
	if len(metadataVersion) != 2 || (metadataVersion[0] != "1" && metadataVersion[0] != "2") {
		return out, errPythonArchive
	}
	minor, e := strconv.Atoi(metadataVersion[1])
	if e != nil || minor < 0 {
		return out, errPythonArchive
	}
	actual := NormalizePython(headers.Get("Name"))
	rawVersion := headers.Get("Version")
	if len(rawVersion) > 100 || actual != name {
		return out, errPythonArchive
	}
	a, e := pep.Parse(rawVersion)
	b, other := pep.Parse(version)
	if e != nil || other != nil || !a.Equal(b) {
		return out, errPythonArchive
	}
	requires := headers.Get("Requires-Python")
	if len(requires) > 4096 || strings.ContainsAny(requires, "\r\n\x00") {
		return out, errPythonArchive
	}
	out = pythonCore{Name: name, Version: a.String(), RequiresPython: requires, Raw: string(raw)}
	return out, nil
}
func pythonArchivePath(name string) bool {
	name = strings.TrimSuffix(name, "/")
	return name != "" && name != "." && name != ".." && npmArchiveText(name) && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && path.Clean(name) == name
}

type pythonArchiveEntry struct {
	kind   byte
	target string
}

func pythonArchiveLinks(entries map[string]pythonArchiveEntry) bool {
	for name := range entries {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if entry, ok := entries[parent]; ok && entry.kind != tar.TypeDir {
				return false
			}
		}
	}
	resolved := map[string]string{}
	for name, entry := range entries {
		if entry.target == "" || resolved[name] != "" {
			continue
		}
		seen := map[string]bool{name: true}
		chain := []string{name}
		target := entry.target
		for {
			if final := resolved[target]; final != "" {
				target = final
				break
			}
			if seen[target] {
				return false
			}
			seen[target] = true
			destination, ok := entries[target]
			if !ok {
				return false
			}
			chain = append(chain, target)
			if destination.target == "" {
				break
			}
			target = destination.target
		}
		for _, member := range chain {
			resolved[member] = target
		}
	}
	for name, entry := range entries {
		if entry.kind == tar.TypeLink && entries[resolved[name]].kind != tar.TypeReg {
			return false
		}
	}
	return true
}

// inspectPythonDistribution uses bounded standard ZIP/tar readers. It never
// extracts files, imports a module or invokes a package's build backend.
func inspectPythonDistribution(ctx context.Context, r io.ReaderAt, size int64, filename string, budget pythonArchiveBudget) (pythonCore, error) {
	name, version, kind, e := pythonDistribution(filename)
	if e != nil || size < 0 || budget.Expanded <= 0 || budget.Expanded >= 1<<62 || budget.Files <= 0 || budget.Metadata <= 0 || budget.Metadata > budget.Expanded {
		return pythonCore{}, errPythonArchive
	}
	var core []byte
	entries := map[string]pythonArchiveEntry{}
	folded := map[string]bool{}
	remaining := budget.Expanded
	add := func(name string, entry pythonArchiveEntry) bool {
		name = strings.TrimSuffix(name, "/")
		lower := strings.ToLower(name)
		if !pythonArchivePath(name) || folded[lower] || len(entries) >= budget.Files {
			return false
		}
		entries[name] = entry
		folded[lower] = true
		return true
	}
	metadataPath := func(p string) bool {
		parts := strings.Split(p, "/")
		if kind == "wheel" {
			if len(parts) != 2 || parts[1] != "METADATA" || !strings.HasSuffix(parts[0], ".dist-info") {
				return false
			}
			stem := strings.TrimSuffix(parts[0], ".dist-info")
			cut := strings.LastIndex(stem, "-")
			if cut < 1 || NormalizePython(stem[:cut]) != name {
				return false
			}
			v, e := pep.Parse(stem[cut+1:])
			expected, _ := pep.Parse(version)
			return e == nil && v.Equal(expected)
		}
		return len(parts) == 2 && parts[1] == "PKG-INFO"
	}
	consume := func(reader io.Reader, length int64, isMetadata bool) error {
		if length < 0 || length > remaining {
			return errPythonArchive
		}
		if isMetadata {
			if core != nil || length > budget.Metadata {
				return errPythonArchive
			}
			var e error
			core, e = io.ReadAll(io.LimitReader(reader, budget.Metadata+1))
			if e != nil || int64(len(core)) > budget.Metadata {
				return errPythonArchive
			}
			remaining -= int64(len(core))
			return nil
		}
		n, e := io.Copy(io.Discard, io.LimitReader(reader, remaining+1))
		remaining -= n
		if e != nil || remaining < 0 {
			return errPythonArchive
		}
		return nil
	}
	if kind == "wheel" || kind == "zip" {
		archive, e := zip.NewReader(r, size)
		if e != nil || len(archive.File) > budget.Files {
			return pythonCore{}, errPythonArchive
		}
		for _, f := range archive.File {
			if ctx.Err() != nil {
				return pythonCore{}, ctx.Err()
			}
			entry := pythonArchiveEntry{kind: tar.TypeReg}
			if f.FileInfo().IsDir() {
				entry.kind = tar.TypeDir
			}
			if !f.Mode().IsRegular() && !f.Mode().IsDir() {
				return pythonCore{}, errPythonArchive
			}
			if !add(f.Name, entry) || f.UncompressedSize64 > uint64(remaining) {
				return pythonCore{}, errPythonArchive
			}
			if kind == "wheel" && len(strings.Split(f.Name, "/")) == 2 && strings.HasSuffix(f.Name, ".dist-info/METADATA") && !metadataPath(f.Name) {
				return pythonCore{}, errPythonArchive
			}
			file, e := f.Open()
			if e != nil {
				return pythonCore{}, errPythonArchive
			}
			e = consume(file, int64(f.UncompressedSize64), metadataPath(f.Name))
			file.Close()
			if e != nil {
				return pythonCore{}, e
			}
		}
	} else {
		compressed := bufio.NewReader(io.NewSectionReader(r, 0, size))
		gz, e := gzip.NewReader(compressed)
		if e != nil {
			return pythonCore{}, errPythonArchive
		}
		defer gz.Close()
		gz.Multistream(false)
		limited := &io.LimitedReader{R: gz, N: budget.Expanded + 1}
		archive := tar.NewReader(limited)
		for {
			if ctx.Err() != nil {
				return pythonCore{}, ctx.Err()
			}
			h, e := archive.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return pythonCore{}, errPythonArchive
			}
			entry := pythonArchiveEntry{kind: h.Typeflag}
			if entry.kind == tar.TypeRegA {
				entry.kind = tar.TypeReg
			}
			if entry.kind == tar.TypeSymlink || entry.kind == tar.TypeLink {
				if h.Linkname == "" || !npmArchiveText(h.Linkname) || path.IsAbs(h.Linkname) {
					return pythonCore{}, errPythonArchive
				}
				entry.target = h.Linkname
				if entry.kind == tar.TypeSymlink {
					entry.target = path.Join(path.Dir(h.Name), h.Linkname)
				}
				root := strings.Split(h.Name, "/")[0]
				if !pythonArchivePath(entry.target) || !(entry.target == root || strings.HasPrefix(entry.target, root+"/")) {
					return pythonCore{}, errPythonArchive
				}
			} else if entry.kind != tar.TypeReg && entry.kind != tar.TypeDir {
				return pythonCore{}, errPythonArchive
			}
			if !add(h.Name, entry) || h.Size < 0 || h.Size > remaining {
				return pythonCore{}, errPythonArchive
			}
			if metadataPath(h.Name) && entry.kind != tar.TypeReg {
				return pythonCore{}, errPythonArchive
			}
			if e = consume(archive, h.Size, metadataPath(h.Name)); e != nil || limited.N <= 0 {
				return pythonCore{}, errPythonArchive
			}
		}
		buffer := make([]byte, 32<<10)
		for {
			n, e := limited.Read(buffer)
			if limited.N <= 0 || bytes.Count(buffer[:n], []byte{0}) != n {
				return pythonCore{}, errPythonArchive
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return pythonCore{}, errPythonArchive
			}
		}
		if _, e = compressed.Peek(1); e != io.EOF {
			return pythonCore{}, errPythonArchive
		}
	}
	if !pythonArchiveLinks(entries) || core == nil {
		return pythonCore{}, errPythonArchive
	}
	return pythonCoreMetadata(core, name, version)
}
