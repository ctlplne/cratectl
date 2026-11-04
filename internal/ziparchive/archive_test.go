// SPDX-License-Identifier: BUSL-1.1
package ziparchive

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func callbackFixture(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, name := range []string{"metadata.txt", "opaque.bin"} {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte("owned inert bytes")); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return 0, nil }

type failedWriter struct{}

func (failedWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }
func TestAdmissionCallbacksAndWritersFailWithoutPartialInventory(t *testing.T) {
	data := callbackFixture(t)
	limits := Limits{1 << 20, 1 << 20, 1 << 16, 16}
	sentinel := errors.New("owned callback rejection")
	for _, tc := range []struct {
		name  string
		admit Admit
		want  error
	}{
		{"callback", func(string, bool, int64) (io.Writer, error) { return nil, sentinel }, sentinel},
		{"short writer", func(string, bool, int64) (io.Writer, error) { return shortWriter{}, nil }, ErrArchive},
		{"failed writer", func(string, bool, int64) (io.Writer, error) { return failedWriter{}, nil }, ErrArchive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := Inspect(context.Background(), bytes.NewReader(data), int64(len(data)), limits, tc.admit)
			if !errors.Is(e, tc.want) || got != (Inventory{}) {
				t.Fatal(got, e)
			}
		})
	}
	var selected bytes.Buffer
	got, e := Inspect(context.Background(), bytes.NewReader(data), int64(len(data)), limits, func(name string, _ bool, _ int64) (io.Writer, error) {
		if name == "metadata.txt" {
			return &selected, nil
		}
		return nil, nil
	})
	if e != nil || got.Files != 2 || got.ExpandedBytes != 34 || selected.String() != "owned inert bytes" {
		t.Fatal(got, e, selected.String())
	}
}
func TestCallbackCancellationDominatesAndLeavesNoInventory(t *testing.T) {
	data := callbackFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, e := Inspect(ctx, bytes.NewReader(data), int64(len(data)), Limits{1 << 20, 1 << 20, 1 << 16, 16}, func(string, bool, int64) (io.Writer, error) { cancel(); return nil, errors.New("owned callback error") })
	if !errors.Is(e, context.Canceled) || got != (Inventory{}) {
		t.Fatal(got, e)
	}
}
