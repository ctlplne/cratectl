// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestNPMGroupDenialAndTagPrecedence(t *testing.T) {
	members := []store.NPMMember{
		{Repository: store.Repository{Name: "first"}, Versions: []store.NPMVersion{{Version: "1.0.0", Blocked: true}}, Tags: map[string]string{"latest": "1.0.0"}},
		{Repository: store.Repository{Name: "second"}, Versions: []store.NPMVersion{{Version: "1.0.0"}, {Version: "2.0.0"}}, Tags: map[string]string{"latest": "2.0.0", "next": "2.0.0"}},
	}
	versions, tags := npmMerge(members)
	if !versions["1.0.0"].Version.Blocked || versions["1.0.0"].Source.Name != "first" || tags["latest"] != "" || tags["next"] != "2.0.0" {
		t.Fatal("group fell through a denied collision or changed tag authority", versions, tags)
	}
}
func TestNPMNormalizedDependencyAndBinBinding(t *testing.T) {
	pkg := map[string]any{"name": "@scope/pkg", "bin": "./cli.js", "dependencies": map[string]any{"dep": "1.0.0"}, "optionalDependencies": map[string]any{"extra": "2.0.0"}, "bundledDependencies": true}
	advertised := map[string]any{"name": "@scope/pkg", "bin": map[string]any{"pkg": "cli.js"}, "dependencies": map[string]any{"dep": "1.0.0", "extra": "2.0.0"}, "optionalDependencies": map[string]any{"extra": "2.0.0"}, "bundleDependencies": []any{"extra", "dep"}}
	raw, _ := json.Marshal(advertised)
	if !npmGraphMatches(pkg, raw) {
		t.Fatal("native package metadata normalization changed graph meaning")
	}
	advertised["bin"] = map[string]any{"pkg": "other.js"}
	raw, _ = json.Marshal(advertised)
	if npmGraphMatches(pkg, raw) {
		t.Fatal("different executable target accepted")
	}
}
func TestNPMSourceAuthorityAndCatalogPin(t *testing.T) {
	repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: "https://registry.example/npm/", Networks: []string{"0.0.0.0/0"}}, DownloadSources: []upstream.Config{{URL: "https://cdn.example/packages/", Networks: []string{"0.0.0.0/0"}, CredentialRef: "cdn"}}}}
	s := New(nil, nil, "https://local.example")
	document := func(url, integrity string) []byte {
		v := map[string]any{"name": "@scope/pkg", "version": "1.0.0", "dependencies": map[string]string{"dep": "1.0.0"}, "dist": map[string]string{"tarball": url, "integrity": integrity}}
		b, _ := json.Marshal(map[string]any{"name": "@scope/pkg", "versions": map[string]any{"1.0.0": v}, "dist-tags": map[string]string{"latest": "1.0.0"}})
		return b
	}
	data := document("https://cdn.example/packages/pkg.tgz", crypt.Integrity([]byte("fixture")))
	catalog, sources, e := s.parseNPMCatalog(data, "@scope/pkg", repo)
	if e != nil || len(sources) != 1 || catalog.Versions["1.0.0"] != sources[0].Key {
		t.Fatal(e)
	}
	_, again, e := s.parseNPMCatalog(data, "@scope/pkg", repo)
	if e != nil || again[0].Key != sources[0].Key {
		t.Fatal("immutable source identity changed")
	}
	for _, url := range []string{"https://evil.example/pkg.tgz", "https://cdn.example/private/pkg.tgz", "https://cdn.example/packages/../private/pkg.tgz", "https://user:password@cdn.example/packages/pkg.tgz", "https://cdn.example/packages/pkg.tgz?secret=private", "http://cdn.example/packages/pkg.tgz"} {
		if _, _, e = s.parseNPMCatalog(document(url, crypt.Integrity([]byte("fixture"))), "@scope/pkg", repo); e == nil {
			t.Fatal("unapproved source accepted", url)
		}
	}
	if _, _, e = s.parseNPMCatalog(document("https://cdn.example/packages/pkg.tgz", ""), "@scope/pkg", repo); e == nil {
		t.Fatal("unpinned source accepted")
	}
	if npmGraphMatches(map[string]any{"dependencies": map[string]any{"dep": "2.0.0"}}, sources[0].Package) {
		t.Fatal("archive/metadata dependency disagreement accepted")
	}
}

func FuzzNPMCatalog(f *testing.F) {
	seed, _ := json.Marshal(map[string]any{"name": "pkg", "versions": map[string]any{"1.0.0": map[string]any{"name": "pkg", "version": "1.0.0", "dist": map[string]string{"tarball": "https://registry.example/pkg.tgz", "integrity": crypt.Integrity([]byte("fixture"))}}}, "dist-tags": map[string]string{"latest": "1.0.0"}})
	f.Add(seed)
	f.Add([]byte(`{"name":"pkg","versions":{},"dist-tags":{}}`))
	f.Add([]byte(`{"name":"pkg","versions":{"1.0.0":{}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		s := New(nil, nil, "https://local.example")
		s.NativeVersionLimit = 64
		s.NativeTagLimit = 32
		repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: "https://registry.example/", Networks: []string{"0.0.0.0/0"}}}}
		catalog, sources, e := s.parseNPMCatalog(data, "pkg", repo)
		if e == nil {
			if len(catalog.Versions) != len(sources) || catalog.Name != "pkg" {
				t.Fatal("catalog/source bindings diverged")
			}
			for _, source := range sources {
				if source.Name != "pkg" || catalog.Versions[source.Version] != source.Key {
					t.Fatal("coordinate escaped catalog")
				}
			}
		}
	})
}
