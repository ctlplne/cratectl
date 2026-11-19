// SPDX-License-Identifier: BUSL-1.1
package conda

import (
	"archive/tar"
	"compress/bzip2"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxArchiveBytes int64 = 64 << 20
const maxExpandedBytes int64 = 256 << 20
const MaxIndexBytes = 128 << 10

var ErrPackage = errors.New("invalid or unsupported Conda tar.bz2 package")

var packageName = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,127}$`)
var versionName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.+!]{0,95}$`)
var buildName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.+]{0,63}$`)
var versionSpec = regexp.MustCompile(`^[a-zA-Z0-9_.*+!<>=|,~()-]+$`)
var buildSpec = regexp.MustCompile(`^[a-zA-Z0-9_.*+]+$`)

func ValidSubdir(value string) bool {
	switch value {
	case "noarch", "linux-64", "linux-aarch64", "linux-armv7l", "linux-ppc64le", "linux-s390x", "linux-riscv64",
		"osx-64", "osx-arm64", "win-64", "win-arm64":
		return true
	}
	return false
}

type Coordinate struct {
	Subdir, Name, Version, Build string
}

func (c Coordinate) FileName() string { return c.Name + "-" + c.Version + "-" + c.Build + ".tar.bz2" }

func (c Coordinate) Path() string { return c.Subdir + "/" + c.FileName() }

func ParsePath(value string) (Coordinate, bool) {
	if len(value) > 320 {
		return Coordinate{}, false
	}
	subdir, file, ok := strings.Cut(value, "/")
	nameAndVersion, suffix := strings.CutSuffix(file, ".tar.bz2")
	separateBuild := strings.LastIndexByte(nameAndVersion, '-')
	if !ok || !suffix || !ValidSubdir(subdir) || separateBuild < 1 {
		return Coordinate{}, false
	}
	prefix, build := nameAndVersion[:separateBuild], nameAndVersion[separateBuild+1:]
	separateVersion := strings.LastIndexByte(prefix, '-')
	if separateVersion < 1 {
		return Coordinate{}, false
	}
	name, version := prefix[:separateVersion], prefix[separateVersion+1:]
	if !packageName.MatchString(name) || !versionName.MatchString(version) || !buildName.MatchString(build) {
		return Coordinate{}, false
	}
	return Coordinate{Subdir: subdir, Name: name, Version: version, Build: build}, true
}

type Package struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Build       string   `json:"build"`
	BuildNumber *int64   `json:"build_number"`
	Subdir      string   `json:"subdir"`
	Depends     []string `json:"depends"`
	Constrains  []string `json:"constrains,omitempty"`
	Noarch      string   `json:"noarch,omitempty"`
	License     string   `json:"license,omitempty"`
	Timestamp   int64    `json:"timestamp,omitempty"`
}

func (p Package) ValidFor(c Coordinate) bool {
	if !ValidSubdir(c.Subdir) || !packageName.MatchString(c.Name) || !versionName.MatchString(c.Version) || !buildName.MatchString(c.Build) ||
		p.Name != c.Name || p.Version != c.Version || p.Build != c.Build || p.Subdir != c.Subdir ||
		p.BuildNumber == nil || *p.BuildNumber < 0 || *p.BuildNumber > 1_000_000_000 || p.Timestamp < 0 || p.Timestamp > 9_999_999_999_999 ||
		len(p.License) > 512 || strings.ContainsFunc(p.License, unicode.IsControl) {
		return false
	}
	if p.Noarch != "" && (c.Subdir != "noarch" || (p.Noarch != "generic" && p.Noarch != "python")) {
		return false
	}
	for _, specs := range [][]string{p.Depends, p.Constrains} {
		if len(specs) > 256 {
			return false
		}
		for _, spec := range specs {
			if !validDependency(spec) {
				return false
			}
		}
	}
	return true
}

func validDependency(spec string) bool {
	if len(spec) > 1024 || strings.ContainsFunc(spec, func(r rune) bool { return r < ' ' || r > '~' }) {
		return false
	}
	parts := strings.Fields(spec)
	return len(parts) >= 1 && len(parts) <= 3 && packageName.MatchString(parts[0]) &&
		(len(parts) < 2 || versionSpec.MatchString(parts[1])) && (len(parts) < 3 || buildSpec.MatchString(parts[2]))
}

type checkedReader struct {
	ctx context.Context
	r   io.Reader
}

func (r checkedReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(data)
}

// Inspect validates an original tar.bz2 and reads only its bounded index
// stanza into memory. It never extracts package files or executes hooks.
func Inspect(ctx context.Context, source io.ReaderAt, size int64, coordinate Coordinate) (Package, error) {
	if source == nil || size < 4 || size > MaxArchiveBytes {
		return Package{}, ErrPackage
	}
	input := checkedReader{ctx, io.NewSectionReader(source, 0, size)}
	payload := &io.LimitedReader{R: bzip2.NewReader(input), N: maxExpandedBytes + 1}
	reader := tar.NewReader(payload)
	seen := make(map[string]bool)
	var index []byte
	for members := 0; ; members++ {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || members >= 10000 {
			if ctx.Err() != nil {
				return Package{}, ctx.Err()
			}
			return Package{}, ErrPackage
		}
		name := strings.TrimSuffix(strings.TrimPrefix(entry.Name, "./"), "/")
		if (name == "." || name == "") && entry.Typeflag == tar.TypeDir && entry.Size == 0 {
			if seen["."] {
				return Package{}, ErrPackage
			}
			seen["."] = true
			continue
		}
		_, duplicate := seen[name]
		directory := entry.Typeflag == tar.TypeDir
		if !safeTarPath(name) || duplicate || (directory && entry.Size != 0) ||
			(!directory && entry.Typeflag != tar.TypeReg && entry.Typeflag != tar.TypeRegA) {
			return Package{}, ErrPackage
		}
		for key := range entry.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") {
				return Package{}, ErrPackage
			}
		}
		seen[name] = directory
		if name == "info/index.json" {
			if entry.Typeflag == tar.TypeDir || entry.Size < 1 || entry.Size > MaxIndexBytes {
				return Package{}, ErrPackage
			}
			index, err = io.ReadAll(reader)
			if err != nil || int64(len(index)) != entry.Size {
				return Package{}, ErrPackage
			}
		}
	}
	for name := range seen {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if directory, found := seen[parent]; found && !directory {
				return Package{}, ErrPackage
			}
		}
	}
	if err := tarPadding(ctx, payload); err != nil {
		return Package{}, err
	}
	if ctx.Err() != nil {
		return Package{}, ctx.Err()
	}
	var metadata Package
	if json.Unmarshal(index, &metadata) != nil || !metadata.ValidFor(coordinate) {
		return Package{}, ErrPackage
	}
	if metadata.Depends == nil {
		metadata.Depends = []string{}
	}
	return metadata, nil
}

func safeTarPath(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 1024 && utf8.ValidString(name) &&
		!strings.ContainsAny(name, "\\:") && !strings.ContainsFunc(name, unicode.IsControl) && path.Clean(name) == name &&
		!strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && strings.Count(name, "/") < 64
}

func tarPadding(ctx context.Context, payload *io.LimitedReader) error {
	var buffer [4096]byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := payload.Read(buffer[:])
		for _, value := range buffer[:n] {
			if value != 0 {
				return ErrPackage
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && payload.N > 0 {
				return nil
			}
			return ErrPackage
		}
	}
}
