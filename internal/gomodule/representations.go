// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/ziparchive"
)

const MaxVersionInfo = 64 << 10

// ParseLatestVersionInfo discovers an advertised canonical coordinate, then
// applies the same exact-field, timestamp and pseudo-version rules as .info.
// The preliminary decode is byte-bounded; it never authorizes a source or bytes.
func ParseLatestVersionInfo(data []byte, mod string) (Info, error) {
	if len(data) > MaxVersionInfo || len(mod) > MaxModulePath || !utf8.Valid(data) {
		return Info{}, ErrModule
	}
	var header struct{ Version string }
	if json.Unmarshal(data, &header) != nil {
		return Info{}, ErrModule
	}
	c, e := Canonical(mod, header.Version)
	if e != nil {
		return Info{}, ErrModule
	}
	return ParseVersionInfo(data, c)
}

// ParseVersionInfo binds upstream metadata to an already canonical coordinate.
// Time is optional in the Go protocol. Unknown future fields are opaque, bounded
// data; they do not supply credentials, sources, executable commands or policy.
// Preserve the caller's original bytes separately instead of reserializing them.
func ParseVersionInfo(data []byte, c Coordinate) (Info, error) {
	if _, e := Canonical(c.Module, c.Version); e != nil || len(data) > MaxVersionInfo || !utf8.Valid(data) {
		return Info{}, ErrModule
	}
	d := json.NewDecoder(bytes.NewReader(data))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return Info{}, ErrModule
	}
	seen := map[string]bool{}
	var out Info
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || seen[name] || len(seen) >= 64 || strings.EqualFold(name, "Version") && name != "Version" || strings.EqualFold(name, "Time") && name != "Time" {
			return Info{}, ErrModule
		}
		seen[name] = true
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return Info{}, ErrModule
		}
		switch name {
		case "Version":
			if json.Unmarshal(raw, &out.Version) != nil || out.Version != c.Version {
				return Info{}, ErrModule
			}
		case "Time":
			var instant string
			if json.Unmarshal(raw, &instant) != nil {
				return Info{}, ErrModule
			}
			// Reuse publication's nonzero/RFC3339/pseudo-version constraints.
			if _, e = VersionInfo(c, instant); e != nil {
				return Info{}, ErrModule
			}
			out.Time, _ = time.Parse(time.RFC3339Nano, instant)
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || !seen["Version"] {
		return Info{}, ErrModule
	}
	if _, e = d.Token(); e != io.EOF {
		return Info{}, ErrModule
	}
	return out, nil
}

// InspectRepresentations checks a complete inert upstream bundle before any
// durable references can be admitted. It does not fetch, publish or trust an
// upstream checksum: a future proxy must apply those separate authority fences.
// This profile still requires a root go.mod; legacy synthesis is not implemented.
func InspectRepresentations(ctx context.Context, input io.ReaderAt, size int64, c Coordinate, mod, info []byte, limits ziparchive.Limits) (Archive, error) {
	if len(mod) > MaxGoMod {
		return Archive{}, ErrModule
	}
	if _, e := ParseVersionInfo(info, c); e != nil {
		return Archive{}, e
	}
	archive, e := InspectArchive(ctx, input, size, c, limits)
	if e != nil {
		return Archive{}, e
	}
	if !bytes.Equal(mod, archive.GoMod) {
		return Archive{}, ErrModule
	}
	return archive, nil
}
