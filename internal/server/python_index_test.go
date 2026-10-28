// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func pythonIndexTestRepo() store.Repository {
	return store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: "https://index.example/simple/", Networks: []string{"0.0.0.0/0"}}, DownloadSources: []upstream.Config{{URL: "https://files.example/packages/", Networks: []string{"0.0.0.0/0"}}}}}
}
func TestPythonIndexFormatsAndBindings(t *testing.T) {
	s := New(nil, nil, "https://local.example")
	repo := pythonIndexTestRepo()
	digest := crypt.Digest([]byte("fixture"))
	core := crypt.Digest([]byte("core"))
	filename := "pkg-1.0-py3-none-any.whl"
	html := `<html><body><a href="https://files.example/packages/` + filename + `#sha256=` + digest + `" data-requires-python="&gt;=3.10" data-yanked="reason &amp; details" data-core-metadata="sha256=` + core + `">` + filename + `</a></body></html>`
	catalog, sources, e := s.parsePythonIndex([]byte(html), "text/html", "https://index.example/simple/pkg/", "pkg", repo)
	if e != nil || len(sources) != 1 || catalog.Files[filename] != sources[0].Key {
		t.Fatal("HTML anchor text or source binding lost", catalog, e)
	}
	var file store.PythonFile
	if json.Unmarshal(sources[0].Metadata, &file) != nil || file.RequiresPython != ">=3.10" || file.Yanked == nil || *file.Yanked != "reason & details" || !file.CoreAvailable {
		t.Fatal("HTML metadata attributes were changed", file)
	}
	document, _ := json.Marshal(map[string]any{"meta": map[string]string{"api-version": "1.0"}, "name": "pkg", "files": []any{map[string]any{"filename": filename, "url": "https://files.example/packages/" + filename, "hashes": map[string]string{"sha256": digest}, "requires-python": ">=3.10", "yanked": "reason & details", "core-metadata": map[string]string{"sha256": core}}}})
	_, jsonSources, e := s.parsePythonIndex(document, "application/vnd.pypi.simple.v1+json", "https://index.example/simple/pkg/", "pkg", repo)
	if e != nil || len(jsonSources) != 1 || jsonSources[0].Key != sources[0].Key {
		t.Fatal("equivalent HTML/JSON indexes changed immutable binding", e)
	}
	for _, bad := range []string{strings.Replace(html, "files.example", "evil.example", 1), strings.Replace(html, "#sha256="+digest, "", 1), strings.Replace(html, `href="`, `href="https://evil.example/f" href="`, 1), strings.Replace(html, filename+`</a>`, `other-1.0-py3-none-any.whl</a>`, 1)} {
		if _, _, e := s.parsePythonIndex([]byte(bad), "text/html", "https://index.example/simple/pkg/", "pkg", repo); e == nil {
			t.Fatal("unbound or ambiguous HTML file accepted")
		}
	}
}
func TestPythonContentNegotiation(t *testing.T) {
	for _, tc := range []struct {
		value string
		json  bool
	}{{"", false}, {"text/html", false}, {"application/vnd.pypi.simple.v1+json, text/html;q=0.1", true}, {"application/vnd.pypi.simple.v1+json;q=0, text/html", false}} {
		actual, e := pythonPrefersJSON(tc.value)
		if e != nil || actual != tc.json {
			t.Fatal(tc, e)
		}
	}
	if _, e := pythonPrefersJSON("application/xml"); e == nil {
		t.Fatal("unsupported representation accepted")
	}
}
func FuzzPythonIndex(f *testing.F) {
	f.Add([]byte(`<a href="https://files.example/packages/pkg-1.0-py3-none-any.whl#sha256=`+crypt.Digest([]byte("fixture"))+`">pkg-1.0-py3-none-any.whl</a>`), "text/html")
	f.Add([]byte(`{"meta":{"api-version":"1.0"},"name":"pkg","files":[]}`), "application/vnd.pypi.simple.v1+json")
	f.Fuzz(func(t *testing.T, data []byte, media string) {
		if len(data) > 64<<10 || len(media) > 128 {
			return
		}
		s := New(nil, nil, "https://local.example")
		s.NativeVersionLimit = 32
		catalog, sources, e := s.parsePythonIndex(data, media, "https://index.example/simple/pkg/", "pkg", pythonIndexTestRepo())
		if e == nil {
			if len(catalog.Files) != len(sources) {
				t.Fatal("catalog/source count diverged")
			}
			for _, source := range sources {
				if source.Name != "pkg" || catalog.Files[source.Coordinate] != source.Key {
					t.Fatal("unbound coordinate accepted")
				}
			}
		}
	})
}
