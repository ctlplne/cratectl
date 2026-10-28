// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/Masterminds/semver/v3"
)

var errNPMArchive = errors.New("invalid or oversized npm package archive")

func npmArchiveText(name string) bool {
	return len(name) <= 2048 && utf8.ValidString(name) && !strings.ContainsAny(name, `\:`) && !strings.ContainsFunc(name, func(r rune) bool { return r < 32 || r == 127 })
}

func npmArchivePath(name string) bool {
	if !npmArchiveText(name) {
		return false
	}
	name = strings.TrimSuffix(name, "/")
	return (name == "package" || strings.HasPrefix(name, "package/")) && path.Clean(name) == name
}

// npmArchivePackage inspects bytes without extracting files or running scripts.
// It reads through the gzip checksum and rejects concatenated/trailing payloads.
// Only package.json is buffered; all other expanded file data is discarded.
func npmArchivePackage(data []byte, name, version string, expanded int64, files int, jsonBytes int64) (map[string]any, error) {
	if expanded <= 0 || expanded >= 1<<62 || files <= 0 || jsonBytes <= 0 || jsonBytes > expanded {
		return nil, errNPMArchive
	}
	compressed := bytes.NewReader(data)
	gz, e := gzip.NewReader(compressed)
	if e != nil {
		return nil, errNPMArchive
	}
	defer gz.Close()
	gz.Multistream(false)
	budget := &io.LimitedReader{R: gz, N: expanded + 1}
	archive := tar.NewReader(budget)
	seen := map[string]bool{}
	links := map[string]string{}
	types := map[string]byte{}
	var logicalBytes int64
	var manifest []byte
	for n := 0; ; n++ {
		h, e := archive.Next()
		if e == io.EOF {
			break
		}
		if e != nil || n >= files || !npmArchivePath(h.Name) {
			return nil, errNPMArchive
		}
		entry := strings.TrimSuffix(h.Name, "/")
		if seen[entry] {
			return nil, errNPMArchive
		}
		seen[entry] = true
		types[entry] = h.Typeflag
		if h.Size < 0 || h.Size > expanded-logicalBytes {
			return nil, errNPMArchive
		}
		logicalBytes += h.Size
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if entry == "package" || h.Size < 0 || h.Size > expanded {
				return nil, errNPMArchive
			}
		case tar.TypeDir:
		case tar.TypeSymlink:
			// A symlink's target is relative to the entry's parent. Hard links
			// instead name a member relative to the archive root.
			if h.Linkname == "" || !npmArchiveText(h.Linkname) || path.IsAbs(h.Linkname) || !npmArchivePath(path.Join(path.Dir(entry), h.Linkname)) {
				return nil, errNPMArchive
			}
			links[entry] = path.Join(path.Dir(entry), h.Linkname)
		case tar.TypeLink:
			if !npmArchivePath(h.Linkname) {
				return nil, errNPMArchive
			}
			links[entry] = h.Linkname
		default:
			return nil, errNPMArchive
		}
		if entry == "package/package.json" {
			if (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) || h.Size > jsonBytes {
				return nil, errNPMArchive
			}
			manifest, e = io.ReadAll(io.LimitReader(archive, jsonBytes+1))
			if e != nil || int64(len(manifest)) > jsonBytes {
				return nil, errNPMArchive
			}
		}
		if _, e = io.Copy(io.Discard, archive); e != nil || budget.N <= 0 {
			return nil, errNPMArchive
		}
	}
	// Standard tar writers may pad the end with zeros. Nonzero trailing data
	// could be a second interpretation of this archive and is rejected.
	buffer := make([]byte, 32<<10)
	for {
		n, e := budget.Read(buffer)
		if bytes.Count(buffer[:n], []byte{0}) != n || budget.N <= 0 {
			return nil, errNPMArchive
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errNPMArchive
		}
	}
	if compressed.Len() != 0 || !utf8.Valid(manifest) {
		return nil, errNPMArchive
	}
	// Do not let one apparently internal link redirect another entry's parent.
	// This is checked after reading all headers, independent of archive order.
	for entry := range seen {
		for parent := path.Dir(entry); parent != "."; parent = path.Dir(parent) {
			if kind, exists := types[parent]; exists && kind != tar.TypeDir {
				return nil, errNPMArchive
			}
		}
	}
	resolved := map[string]string{}
	for entry, target := range links {
		if resolved[entry] != "" {
			continue
		}
		visited := map[string]bool{entry: true}
		chain := []string{entry}
		for {
			if final := resolved[target]; final != "" {
				target = final
				break
			}
			if visited[target] || (target != "package" && !seen[target]) {
				return nil, errNPMArchive
			}
			visited[target] = true
			chain = append(chain, target)
			if next := links[target]; next != "" {
				target = next
				continue
			}
			break
		}
		for _, member := range chain {
			resolved[member] = target
		}
	}
	for entry := range links {
		if types[entry] == tar.TypeLink && types[resolved[entry]] != tar.TypeReg && types[resolved[entry]] != tar.TypeRegA {
			return nil, errNPMArchive
		}
	}
	var pkg map[string]any
	decoder := json.NewDecoder(bytes.NewReader(manifest))
	decoder.UseNumber()
	if decoder.Decode(&pkg) != nil || pkg == nil || pkg["name"] != name {
		return nil, errNPMArchive
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errNPMArchive
	}
	insideVersion, ok := pkg["version"].(string)
	if !ok || len(insideVersion) > 128 {
		return nil, errNPMArchive
	}
	inside, e := semver.NewVersion(insideVersion)
	outside, outsideErr := semver.StrictNewVersion(version)
	if e != nil || outsideErr != nil || inside.Compare(outside) != 0 {
		return nil, errNPMArchive
	}
	// npm normalizes the publication coordinate, including stripping build
	// metadata in current clients. All other package fields come from the bytes.
	pkg["version"] = version
	return pkg, nil
}
