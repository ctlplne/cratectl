// SPDX-License-Identifier: BUSL-1.1
package cran

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"

	"ctlplne.dev/cratectl/internal/ziparchive"
)

var binaryDirectory = regexp.MustCompile(`^bin/(windows|macosx/(sonoma-arm64|big-sur-arm64|big-sur-x86_64))/contrib/([1-9][0-9]?\.(?:0|[1-9][0-9]?))/$`)
var darwinTarget = regexp.MustCompile(`^(aarch64|x86_64)-apple-darwin[0-9]+(?:\.[0-9]+)*$`)
var patchNumber = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,3})$`)

type BinaryChannel struct {
	directory, series, arch string
	windows                 bool
}

func ParseBinaryChannel(directory string) (BinaryChannel, bool) {
	parts := binaryDirectory.FindStringSubmatch(directory)
	if parts == nil {
		return BinaryChannel{}, false
	}
	channel := BinaryChannel{directory: directory, series: parts[3], windows: parts[1] == "windows", arch: "x86_64"}
	if strings.HasSuffix(parts[2], "-arm64") {
		channel.arch = "aarch64"
	}
	return channel, true
}

func (c BinaryChannel) Directory() string { return c.directory }

func (c BinaryChannel) MediaType() string {
	if c.windows {
		return "application/zip"
	}
	return "application/gzip"
}

func ParseBinaryPath(request string) (BinaryChannel, Coordinate, bool) {
	separator := strings.LastIndexByte(request, '/')
	if separator < 0 {
		return BinaryChannel{}, Coordinate{}, false
	}
	channel, valid := ParseBinaryChannel(request[:separator+1])
	if !valid {
		return BinaryChannel{}, Coordinate{}, false
	}
	extension := ".tgz"
	if channel.windows {
		extension = ".zip"
	}
	file, ok := strings.CutSuffix(request[separator+1:], extension)
	if !ok {
		return BinaryChannel{}, Coordinate{}, false
	}
	coordinate, ok := ParsePath(SourceDirectory + file + ".tar.gz")
	return channel, coordinate, ok
}

// ValidBuilt binds the inspected DESCRIPTION to the requested R series and
// target metadata. The marker and opaque compiled files cannot prove ABI fit.
func (c BinaryChannel) ValidBuilt(line string, p Package) bool {
	if c.directory == "" || len(line) > 256 || strings.ContainsFunc(line, unicode.IsControl) {
		return false
	}
	parts := strings.Split(line, ";")
	if len(parts) != 4 || strings.TrimSpace(parts[2]) == "" {
		return false
	}
	patch, version := strings.CutPrefix(parts[0], "R "+c.series+".")
	if !version || !patchNumber.MatchString(patch) {
		return false
	}
	target, os := strings.TrimSpace(parts[1]), strings.TrimSpace(parts[3])
	if target == "" && p["NeedsCompilation"] != "yes" {
		// Stock R omits the target when building a package without native code.
		return os == "unix" && !c.windows || os == "windows" && c.windows
	}
	if c.windows {
		return os == "windows" && target == "x86_64-w64-mingw32"
	}
	return os == "unix" && strings.HasPrefix(target, c.arch+"-") && darwinTarget.MatchString(target)
}

// InspectBinary reads plain DESCRIPTION and only checks that the installed
// metadata file exists. The R serialization and compiled files remain opaque.
func InspectBinary(ctx context.Context, source io.ReaderAt, size int64, channel BinaryChannel, coordinate Coordinate) (Package, string, error) {
	var description []byte
	var err error
	if channel.windows {
		description, err = inspectBinaryZIP(ctx, source, size, coordinate.Name)
	} else {
		description, err = inspectTar(ctx, source, size, coordinate.Name, true)
	}
	if err != nil {
		return nil, "", err
	}
	var built string
	metadata, err := parseDescription(description, coordinate, &built)
	if err != nil || !channel.ValidBuilt(built, metadata) {
		return nil, "", ErrPackage
	}
	return metadata, built, nil
}

func inspectBinaryZIP(ctx context.Context, source io.ReaderAt, size int64, name string) ([]byte, error) {
	var description bytes.Buffer
	var installedMetadata bool
	_, err := ziparchive.Inspect(ctx, source, size, ziparchive.Limits{
		CompressedBytes: MaxArchiveBytes, ExpandedBytes: maxExpandedBytes, DirectoryBytes: 4 << 20, Files: 10000,
	}, func(file string, directory bool, expandedBytes int64) (io.Writer, error) {
		file = strings.TrimSuffix(file, "/")
		if (file != name && !strings.HasPrefix(file, name+"/")) || (file == name && !directory) || strings.Contains(file, ":") {
			return nil, ErrPackage
		}
		switch file {
		case name + "/DESCRIPTION":
			if directory || expandedBytes < 1 || expandedBytes > MaxDescriptionBytes {
				return nil, ErrPackage
			}
			return &description, nil
		case name + "/Meta/package.rds":
			installedMetadata = !directory && expandedBytes > 0
		}
		return nil, nil
	})
	if errors.Is(err, ziparchive.ErrArchive) || !installedMetadata && err == nil {
		return nil, ErrPackage
	}
	return description.Bytes(), err
}
