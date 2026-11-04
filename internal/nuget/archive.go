// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"bytes"
	"context"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

var ErrArchive = ziparchive.ErrArchive

type ArchiveLimits = ziparchive.Limits

type ArchiveIdentity struct {
	Identity      NuspecIdentity
	NuspecPath    string
	Nuspec        []byte
	Files         int
	ExpandedBytes int64
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

// InspectArchive retains only bounded Nuspec bytes after the shared structural
// ZIP checks succeed. A parser error never returns partial package identity.
func InspectArchive(ctx context.Context, input io.ReaderAt, size int64, limits ArchiveLimits) (out ArchiveIdentity, err error) {
	defer func() {
		if ctx.Err() != nil {
			out, err = ArchiveIdentity{}, ctx.Err()
		}
	}()
	var manifest bytes.Buffer
	manifestPath := ""
	inventory, err := ziparchive.Inspect(ctx, input, size, limits, func(name string, directory bool, expanded int64) (io.Writer, error) {
		if !archivePath(name) {
			return nil, ErrArchive
		}
		extension := path.Ext(name)
		if path.Dir(name) == "." && len(extension) == len(".nuspec") && strings.EqualFold(extension, ".nuspec") {
			if manifestPath != "" || directory || expanded > MaxNuspecBytes {
				return nil, ErrArchive
			}
			manifestPath = name
			return &manifest, nil
		}
		return nil, nil
	})
	if err != nil {
		return ArchiveIdentity{}, err
	}
	if manifestPath == "" {
		return ArchiveIdentity{}, ErrArchive
	}
	identity, err := ParseNuspecIdentity(ctx, manifest.Bytes())
	if err != nil {
		return ArchiveIdentity{}, ErrArchive
	}
	if err = ctx.Err(); err != nil {
		return ArchiveIdentity{}, err
	}
	return ArchiveIdentity{Identity: identity, NuspecPath: manifestPath, Nuspec: manifest.Bytes(), Files: inventory.Files, ExpandedBytes: inventory.ExpandedBytes}, nil
}
