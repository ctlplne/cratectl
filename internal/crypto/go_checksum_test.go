// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

func TestGoDirectoryHashAgreesWithStandardHashAcrossStreamingAndOrdering(t *testing.T) {
	files := map[string]string{
		"go.cratectl.invalid/Owned/module@v1.2.3/":       "",
		"go.cratectl.invalid/Owned/module@v1.2.3/go.mod": "// original bytes\r\nmodule go.cratectl.invalid/Owned/module\r\n",
		"go.cratectl.invalid/Owned/module@v1.2.3/a.go":   "package owned\n",
		"go.cratectl.invalid/Owned/module@v1.2.3/Σ.txt":  "inert contents\x00\xff\n",
	}
	orders := [][]string{{}, {"go.cratectl.invalid/Owned/module@v1.2.3/Σ.txt", "go.cratectl.invalid/Owned/module@v1.2.3/a.go", "go.cratectl.invalid/Owned/module@v1.2.3/go.mod", "go.cratectl.invalid/Owned/module@v1.2.3/"}}
	for name := range files {
		orders[0] = append(orders[0], name)
	}
	want, err := dirhash.Hash1(orders[0], func(name string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(files[name])), nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range orders {
		for _, chunk := range []int{1, 7, 1024} {
			h, err := NewGoDirectoryHash(len(files), 4096)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range order {
				writer, err := h.File(name, int64(len(files[name])))
				if err != nil {
					t.Fatal(err)
				}
				data := []byte(files[name])
				for len(data) > 0 {
					n := min(len(data), chunk)
					if _, err := writer.Write(data[:n]); err != nil {
						t.Fatal(err)
					}
					data = data[n:]
				}
			}
			got, err := h.Sum()
			if err != nil || got != want {
				t.Fatal("streaming checksum differs from standard Go", got, want, err)
			}
			if again, err := h.Sum(); err != nil || again != got {
				t.Fatal("sealed checksum changed", err)
			}
			if _, err := h.File("late", 0); !errors.Is(err, ErrGoChecksum) {
				t.Fatal("sealed inventory admitted another file")
			}
		}
	}
}

func TestGoDirectoryHashRejectsAmbiguousPartialAndOversizedInput(t *testing.T) {
	for _, test := range []struct {
		files int
		names int64
	}{{0, 1}, {65535, 1}, {1, 0}, {1, 128<<20 + 1}} {
		if h, err := NewGoDirectoryHash(test.files, test.names); h != nil || !errors.Is(err, ErrGoChecksum) {
			t.Fatal("invalid allocation budget accepted")
		}
	}
	for _, scenario := range []string{"duplicate", "count", "names", "empty", "newline", "invalid-utf8", "negative", "partial", "overflow"} {
		t.Run(scenario, func(t *testing.T) {
			h, _ := NewGoDirectoryHash(1, 3)
			name, size := "abc", int64(2)
			switch scenario {
			case "empty":
				name = ""
			case "newline":
				name = "a\nb"
			case "invalid-utf8":
				name = "a\xff"
			case "negative":
				size = -1
			case "names":
				name = "abcd"
			}
			writer, err := h.File(name, size)
			if err == nil {
				switch scenario {
				case "duplicate":
					_, err = h.File(name, 0)
				case "count":
					_, err = h.File("x", 0)
				case "partial":
					_, err = writer.Write([]byte("a"))
				case "overflow":
					_, err = writer.Write([]byte("abc"))
				default:
					t.Fatal("invalid file admission succeeded")
				}
			}
			if scenario != "partial" && !errors.Is(err, ErrGoChecksum) {
				t.Fatal("invalid operation did not fail", err)
			}
			if sum, err := h.Sum(); sum != "" || !errors.Is(err, ErrGoChecksum) {
				t.Fatal("failed inventory returned a checksum", err)
			}
		})
	}
}

func TestGoModHashBindsOriginalBytesAsSingleGoModFile(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("module go.cratectl.invalid/owned\n"), []byte("module go.cratectl.invalid/owned\r\n")} {
		want, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil })
		got, gotErr := GoModHash(data)
		if err != nil || gotErr != nil || got != want || !validGoH1(got) {
			t.Fatal("go.mod checksum differs", gotErr, err)
		}
	}
	a, _ := GoModHash([]byte("module go.cratectl.invalid/owned\n"))
	b, _ := GoModHash([]byte("module go.cratectl.invalid/owned\r\n"))
	if a == b {
		t.Fatal("go.mod bytes were normalized")
	}
}
