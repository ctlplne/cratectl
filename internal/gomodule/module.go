// SPDX-License-Identifier: BUSL-1.1
// Package gomodule validates native module identities and inert publication bytes.
package gomodule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"
	"unicode"

	"ctlplne.dev/cratectl/internal/ziparchive"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

var ErrModule = errors.New("invalid, ambiguous, unsupported or oversized Go module")

const MaxModulePath = 512
const MaxVersion = 128
const MaxGoMod = 1 << 20

type Coordinate struct{ Module, Version string }

func Canonical(m, v string) (Coordinate, error) {
	if len(m) > MaxModulePath || len(v) > MaxVersion || module.Check(m, v) != nil || module.CanonicalVersion(v) != v {
		return Coordinate{}, ErrModule
	}
	return Coordinate{m, v}, nil
}

func (c Coordinate) Prefix() string {
	if _, e := Canonical(c.Module, c.Version); e != nil {
		return ""
	}
	m, e := module.EscapePath(c.Module)
	if e != nil {
		return ""
	}
	v, e := module.EscapeVersion(c.Version)
	if e != nil {
		return ""
	}
	return m + "/@v/" + v
}

type Request struct {
	Coordinate
	Operation string
}

// ParseRequest rejects aliases instead of mapping distinct URLs to one identity.
// Inputs are already URL-decoded once by net/http; percent escapes are not Go's
// uppercase escape convention (a literal '!' followed by a lowercase letter).
func ParseRequest(p string) (Request, error) {
	if len(p) > 2048 {
		return Request{}, ErrModule
	}
	escaped, op, ok := strings.Cut(p, "/@v/")
	if !ok {
		if !strings.HasSuffix(p, "/@latest") {
			return Request{}, ErrModule
		}
		escaped, op = strings.TrimSuffix(p, "/@latest"), "latest"
	}
	m, e := module.UnescapePath(escaped)
	if e != nil || len(m) > MaxModulePath {
		return Request{}, ErrModule
	}
	canonical, e := module.EscapePath(m)
	if e != nil || canonical != escaped {
		return Request{}, ErrModule
	}
	if op == "list" || !ok && op == "latest" {
		return Request{Coordinate: Coordinate{Module: m}, Operation: op}, nil
	}
	extension := path.Ext(op)
	if extension != ".info" && extension != ".mod" && extension != ".zip" {
		return Request{}, ErrModule
	}
	v, e := module.UnescapeVersion(strings.TrimSuffix(op, extension))
	if e != nil {
		return Request{}, ErrModule
	}
	c, e := Canonical(m, v)
	if e != nil || c.Prefix()+extension != p {
		return Request{}, ErrModule
	}
	return Request{Coordinate: c, Operation: extension[1:]}, nil
}

type Info struct {
	Version string
	Time    time.Time
}

// VersionInfo produces stable bytes for a caller-supplied publication instant.
// A retry must retain that instant; serving never synthesizes a new timestamp.
func VersionInfo(c Coordinate, instant string) ([]byte, error) {
	if _, e := Canonical(c.Module, c.Version); e != nil || len(instant) > 64 {
		return nil, ErrModule
	}
	t, e := time.Parse(time.RFC3339Nano, instant)
	if e != nil || t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return nil, ErrModule
	}
	return json.Marshal(Info{c.Version, t.UTC()})
}

type Archive struct {
	GoMod         []byte
	Files         int
	ExpandedBytes int64
}

func simpleFold(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		return least
	}, s)
}

// InspectArchive validates the exact module ZIP and retains only its root go.mod.
// No files are extracted, packages compiled, directives executed or VCS invoked.
// This admission profile requires a root go.mod; legacy modules without one and
// ZIP64/split archives need separate implementation and qualification.
func InspectArchive(ctx context.Context, input io.ReaderAt, size int64, c Coordinate, limits ziparchive.Limits) (out Archive, err error) {
	defer func() {
		if ctx.Err() != nil {
			out, err = Archive{}, ctx.Err()
		}
	}()
	if _, err = Canonical(c.Module, c.Version); err != nil {
		return Archive{}, err
	}
	prefix := c.Module + "@" + c.Version + "/"
	var manifest bytes.Buffer
	found := false
	// Record implicit parents too: Dir/a and dir/b collide even without a Dir/ entry.
	type entry struct {
		name      string
		directory bool
		explicit  bool
	}
	names := map[string]entry{}
	admitName := func(name string, directory bool, explicit bool) error {
		key := simpleFold(name)
		if previous, ok := names[key]; ok {
			if previous.name != name || previous.directory != directory || explicit && previous.explicit {
				return ErrModule
			}
			previous.explicit = previous.explicit || explicit
			names[key] = previous
		} else {
			names[key] = entry{name, directory, explicit}
		}
		return nil
	}
	inventory, err := ziparchive.Inspect(ctx, input, size, limits, func(name string, directory bool, expanded int64) (io.Writer, error) {
		if !strings.HasPrefix(name, prefix) {
			return nil, ErrModule
		}
		rel := strings.TrimSuffix(strings.TrimPrefix(name, prefix), "/")
		if rel == "" {
			if directory {
				return nil, nil
			}
			return nil, ErrModule
		}
		if module.CheckFilePath(rel) != nil || admitName(rel, directory, true) != nil {
			return nil, ErrModule
		}
		for parent := path.Dir(rel); parent != "."; parent = path.Dir(parent) {
			if admitName(parent, true, false) != nil {
				return nil, ErrModule
			}
		}
		if strings.EqualFold(path.Base(rel), "go.mod") {
			if rel != "go.mod" || directory || found || expanded > MaxGoMod {
				return nil, ErrModule
			}
			found = true
			return &manifest, nil
		}
		return nil, nil
	})
	if err != nil {
		return Archive{}, err
	}
	if !found {
		return Archive{}, ErrModule
	}
	parsed, e := modfile.ParseLax("go.mod", manifest.Bytes(), nil)
	if e != nil || parsed.Module == nil || parsed.Module.Mod.Path != c.Module {
		return Archive{}, ErrModule
	}
	return Archive{GoMod: manifest.Bytes(), Files: inventory.Files, ExpandedBytes: inventory.ExpandedBytes}, nil
}
