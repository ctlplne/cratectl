// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// Modern modules explicitly retain the requirements for their full imported
// package graph. Files are inert fixture bytes: never compiled or executed.
func nativeCommonGraphZIP(t testing.TB, modules []string, index int) []byte {
	t.Helper()
	var mod strings.Builder
	fmt.Fprintf(&mod, "module %s\n\ngo 1.26.0\n", modules[index])
	if index+1 < len(modules) {
		mod.WriteString("require (\n")
		for n := index + 1; n < len(modules); n++ {
			fmt.Fprintf(&mod, "\t%s v1.0.0", modules[n])
			if n != index+1 {
				mod.WriteString(" // indirect")
			}
			mod.WriteByte('\n')
		}
		mod.WriteString(")\n")
	}
	source := "package owned\n"
	if index+1 < len(modules) {
		source += "import _ " + strconv.Quote(modules[index+1]) + "\n"
	}
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	for _, item := range []struct{ name, raw string }{{"go.mod", mod.String()}, {"owned.go", source}, {"assets/owned.txt", "owned inert graph asset"}} {
		file, err := z.Create(modules[index] + "@v1.0.0/" + item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, item.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

// Derive transitive requirements from actual source imports, independently of
// the fixture writer. The old direct-only modern go.mod must fail this check.
func nativeGraphRequirements(modules map[string]*modfile.File, imports map[string][]string) error {
	for name, manifest := range modules {
		reachable := map[string]bool{}
		var visit func(string) error
		visit = func(module string) error {
			if reachable[module] {
				return nil
			}
			if modules[module] == nil {
				return fmt.Errorf("missing imported module")
			}
			reachable[module] = true
			for _, next := range imports[module] {
				if err := visit(next); err != nil {
					return err
				}
			}
			return nil
		}
		for _, next := range imports[name] {
			if err := visit(next); err != nil {
				return err
			}
		}
		declared := map[string]bool{}
		for _, requirement := range manifest.Require {
			declared[requirement.Mod.Path] = true
			if requirement.Mod.Version != "v1.0.0" {
				return fmt.Errorf("fixture requirement version differs")
			}
			direct := false
			for _, next := range imports[name] {
				direct = direct || next == requirement.Mod.Path
			}
			if requirement.Indirect == direct {
				return fmt.Errorf("fixture direct/indirect declaration differs from its source")
			}
		}
		if manifest.Go == nil || manifest.Go.Version != "1.26.0" || !reflect.DeepEqual(reachable, declared) {
			return fmt.Errorf("modern fixture omits or invents imported transitive requirements")
		}
	}
	return nil
}

func TestCommonGraphFixtureIncludesModernTransitiveRequirementsAndRefusesOriginalHole(t *testing.T) {
	names := make([]string, 8)
	for n := range names {
		names[n] = fmt.Sprintf("go.cratectl.invalid/Owned/node%d", n)
	}
	modules, imports := map[string]*modfile.File{}, map[string][]string{}
	for n, name := range names {
		raw := nativeCommonGraphZIP(t, names, n)
		archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range archive.File {
			file, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(file, 64<<10))
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
			switch strings.TrimPrefix(entry.Name, name+"@v1.0.0/") {
			case "go.mod":
				modules[name], err = modfile.Parse("go.mod", body, nil)
			case "owned.go":
				source, parseErr := parser.ParseFile(token.NewFileSet(), "owned.go", body, parser.ImportsOnly)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				for _, item := range source.Imports {
					next, err := strconv.Unquote(item.Path.Value)
					if err != nil {
						t.Fatal(err)
					}
					imports[name] = append(imports[name], next)
				}
			case "assets/owned.txt":
				if string(body) != "owned inert graph asset" {
					t.Fatal("inert fixture bytes changed")
				}
			default:
				t.Fatal("unexpected native fixture member")
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := nativeGraphRequirements(modules, imports); err != nil {
		t.Fatal(err)
	}
	if err := modules[names[0]].DropRequire(names[7]); err != nil {
		t.Fatal(err)
	}
	if err := nativeGraphRequirements(modules, imports); err == nil {
		t.Fatal("the original incomplete modern graph escaped the regression")
	}
}
