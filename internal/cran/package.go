// SPDX-License-Identifier: BUSL-1.1
package cran

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
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
const MaxDescriptionBytes = 128 << 10
const SourceDirectory = "src/contrib/"
const ArchiveDirectory = SourceDirectory + "Archive/"

var ErrPackage = errors.New("invalid or unsupported CRAN source package")

const namePattern = `[A-Za-z][A-Za-z0-9.]{0,126}[A-Za-z0-9]`
const versionPattern = `[0-9]+(?:[.-][0-9]+)+`

var packageName = regexp.MustCompile(`^` + namePattern + `$`)
var versionName = regexp.MustCompile(`^` + versionPattern + `$`)
var fieldName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_@./-]{0,127}$`)
var dependency = regexp.MustCompile(`^(R|` + namePattern + `)(?: \((?:>=|<=|==|!=|>|<) (?:` + versionPattern + `|r[0-9]+)\))?$`)
var architectures = regexp.MustCompile(`^[A-Za-z0-9_+-]+(?: [A-Za-z0-9_+-]+)*$`)

type Coordinate struct {
	Name, Version string
}

func ValidName(value string) bool { return packageName.MatchString(value) }

func (c Coordinate) Path() string {
	return SourceDirectory + c.Name + "_" + c.Version + ".tar.gz"
}

func ParsePath(value string) (Coordinate, bool) {
	file, prefix := strings.CutPrefix(value, SourceDirectory)
	file, suffix := strings.CutSuffix(file, ".tar.gz")
	name, version, ok := strings.Cut(file, "_")
	if !prefix || !suffix || !ok || len(version) > 80 || !ValidName(name) || !versionName.MatchString(version) {
		return Coordinate{}, false
	}
	return Coordinate{Name: name, Version: version}, true
}

var indexFields = []string{"Package", "Version", "Priority", "Depends", "Imports", "LinkingTo", "Suggests", "Enhances",
	"OS_type", "License", "License_is_FOSS", "License_restricts_use", "Archs", "NeedsCompilation", "Title", "Description"}

type Package map[string]string

func (p Package) ValidFor(c Coordinate) bool {
	if !ValidName(c.Name) || len(c.Version) > 80 || !versionName.MatchString(c.Version) ||
		p["Package"] != c.Name || p["Version"] != c.Version {
		return false
	}
	known := 0
	for _, field := range indexFields {
		value, present := p[field]
		if !present {
			continue
		}
		known++
		if value == "" || len(value) > 8192 || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
			return false
		}
		switch field {
		case "Depends", "Imports", "LinkingTo", "Suggests", "Enhances":
			parts := strings.Split(value, ",")
			if len(parts) > 128 {
				return false
			}
			for _, part := range parts {
				if !dependency.MatchString(strings.TrimSpace(part)) {
					return false
				}
			}
		case "Priority":
			if value != "base" && value != "recommended" {
				return false
			}
		case "OS_type":
			if value != "unix" && value != "windows" {
				return false
			}
		case "NeedsCompilation", "License_is_FOSS", "License_restricts_use":
			if value != "yes" && value != "no" {
				return false
			}
		case "Archs":
			if !architectures.MatchString(value) {
				return false
			}
		}
	}
	return known == len(p)
}

// IndexEntry writes only validated DESCRIPTION fields. Compatibility metadata
// is derived from the original source artifact rather than supplied by it.
func (p Package) IndexEntry(md5 string) string {
	var output strings.Builder
	for _, field := range indexFields {
		if value, ok := p[field]; ok {
			output.WriteString(field + ": " + value + "\n")
		}
	}
	output.WriteString("MD5sum: " + md5 + "\n\n")
	return output.String()
}

func parseDescription(description []byte, c Coordinate) (Package, error) {
	if len(description) < 1 || len(description) > MaxDescriptionBytes || !utf8.Valid(description) {
		return nil, ErrPackage
	}
	fields := make(map[string][]string)
	seen := make(map[string]bool)
	current := ""
	ended := false
	for line := range strings.SplitSeq(string(description), "\n") {
		line = strings.TrimSuffix(line, "\r")
		contents := strings.TrimSpace(line)
		if contents == "" {
			ended = len(fields) > 0
			continue
		}
		if ended || len(line) > 16384 || strings.ContainsFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) {
			return nil, ErrPackage
		}
		if line[0] == ' ' || line[0] == '\t' {
			if current == "" {
				return nil, ErrPackage
			}
			fields[current] = append(fields[current], contents)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		folded := strings.ToLower(key)
		if !ok || !fieldName.MatchString(key) || seen[folded] || len(fields) >= 256 {
			return nil, ErrPackage
		}
		seen[folded] = true
		current = key
		fields[key] = []string{strings.TrimSpace(value)}
	}
	if values := fields["Type"]; len(values) != 0 && !equalDescriptionWord(values, "Package") {
		return nil, ErrPackage
	}
	if values := fields["Encoding"]; len(values) != 0 && !equalDescriptionWord(values, "UTF-8") {
		return nil, ErrPackage
	}
	metadata := make(Package)
	for _, key := range indexFields {
		if parts, ok := fields[key]; ok {
			if value := strings.Join(strings.Fields(strings.Join(parts, " ")), " "); value != "" {
				metadata[key] = value
			}
		}
	}
	if !metadata.ValidFor(c) {
		return nil, ErrPackage
	}
	return metadata, nil
}

func equalDescriptionWord(parts []string, word string) bool {
	return len(parts) == 1 && parts[0] == word
}

type cancellationReader struct {
	ctx context.Context
	r   io.Reader
}

func (r cancellationReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(data)
}

// Inspect reads the one DESCRIPTION in a bounded source tarball without
// extracting, compiling or evaluating any package files.
func Inspect(ctx context.Context, source io.ReaderAt, size int64, c Coordinate) (Package, error) {
	if source == nil || size < 18 || size > MaxArchiveBytes || !ValidName(c.Name) {
		return nil, ErrPackage
	}
	input := bufio.NewReader(cancellationReader{ctx, io.NewSectionReader(source, 0, size)})
	gz, err := gzip.NewReader(input)
	if err != nil {
		return nil, ErrPackage
	}
	defer gz.Close()
	gz.Multistream(false)
	payload := &io.LimitedReader{R: cancellationReader{ctx, gz}, N: maxExpandedBytes + 1}
	archive := tar.NewReader(payload)
	seen := make(map[string]bool)
	var description []byte
	for count := 0; ; count++ {
		member, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || count >= 10000 {
			return nil, ErrPackage
		}
		name := strings.TrimSuffix(strings.TrimPrefix(member.Name, "./"), "/")
		if (name != c.Name && !strings.HasPrefix(name, c.Name+"/")) || len(name) > 1024 || !utf8.ValidString(name) ||
			strings.ContainsAny(name, "\\:") || strings.ContainsFunc(name, unicode.IsControl) || path.Clean(name) != name ||
			strings.Count(name, "/") >= 64 {
			return nil, ErrPackage
		}
		directory := member.Typeflag == tar.TypeDir
		if _, exists := seen[name]; exists || (directory && member.Size != 0) || (name == c.Name && !directory) ||
			(!directory && member.Typeflag != tar.TypeReg && member.Typeflag != tar.TypeRegA) {
			return nil, ErrPackage
		}
		for key := range member.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") {
				return nil, ErrPackage
			}
		}
		seen[name] = directory
		if name == c.Name+"/DESCRIPTION" {
			if directory || member.Size < 1 || member.Size > MaxDescriptionBytes {
				return nil, ErrPackage
			}
			description, err = io.ReadAll(archive)
			if err != nil || int64(len(description)) != member.Size {
				return nil, ErrPackage
			}
		}
	}
	for name := range seen {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if directory, found := seen[parent]; found && !directory {
				return nil, ErrPackage
			}
		}
	}
	var padding [4096]byte
	for {
		n, err := payload.Read(padding[:])
		for _, value := range padding[:n] {
			if value != 0 {
				return nil, ErrPackage
			}
		}
		if errors.Is(err, io.EOF) && payload.N > 0 {
			break
		}
		if err != nil {
			return nil, ErrPackage
		}
	}
	if _, err := input.ReadByte(); !errors.Is(err, io.EOF) {
		return nil, ErrPackage
	}
	return parseDescription(description, c)
}
