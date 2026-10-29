// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func TestOCICompleteCatalogWalksOpaqueAndSignedPageLinks(t *testing.T) {
	for _, kind := range []string{"referrers", "tags/list"} {
		t.Run(kind, func(t *testing.T) {
			var pages atomic.Int32
			subject := "sha256:" + strings.Repeat("a", 64)
			write := func(w http.ResponseWriter) {
				if kind == "referrers" {
					w.Header().Set("Content-Type", testOCIIndex)
					io.WriteString(w, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
				} else {
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"name":"app","tags":[]}`)
				}
			}
			cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pages.Add(1)
				if r.URL.RawQuery != "signature=owned%2Fopaque&cursor=two" || r.Header.Get("Authorization") != "" {
					t.Error("page URI or credential boundary changed")
				}
				write(w)
			}))
			defer cdn.Close()
			path := "app/" + kind
			if kind == "referrers" {
				path += "/" + subject
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/"+path {
					w.WriteHeader(404)
					return
				}
				pages.Add(1)
				if kind == "referrers" && r.URL.Query().Get("cursor") == "two" {
					write(w)
					return
				}
				if kind == "referrers" {
					w.Header().Set("Link", `<?cursor=two>; rel="next"`)
				} else {
					w.Header().Set("Link", fmt.Sprintf(`<%s/pages/tags?signature=owned%%2Fopaque&cursor=two>; rel="next"`, cdn.URL))
				}
				write(w)
			}))
			defer origin.Close()
			server := New(nil, nil, "")
			server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}, DownloadSources: []upstream.Config{{URL: cdn.URL + "/pages/", Networks: []string{"127.0.0.1/32"}, AllowSignedQuery: true}}}}
			i := store.Identity{Tenant: "test-a"}
			client, e := server.newOCIRegistryClient(i, repo, "app")
			if e != nil {
				t.Fatal(e)
			}
			defer client.close()
			response, e := client.get(context.Background(), path, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			g := ociGraphFill{server: server, client: client, ctx: context.Background(), identity: i, repo: repo, image: "app", objects: map[string]store.Artifact{}, stack: map[string]bool{}}
			if _, e = g.catalog(kind, subject, response); e != nil || pages.Load() != 2 {
				t.Fatalf("complete catalog pagination failed: %v pages=%d", e, pages.Load())
			}
		})
	}
}

func TestOCINextLinkGrammarAndAmbiguity(t *testing.T) {
	cases := []struct {
		header []string
		want   string
		bad    bool
	}{
		{[]string{`<https://cdn.example/pages?signature=a,b&cursor=two>; title="a,b"; rel="next"`}, "https://cdn.example/pages?signature=a,b&cursor=two", false},
		{[]string{`<?cursor=old>; rel="prev", <?cursor=new>; rel="next"`}, "?cursor=new", false},
		{[]string{`<?cursor=old>; rel="prev"`, `<?cursor=new>; rel="NEXT"`}, "?cursor=new", false},
		{[]string{`<?cursor=next>; rel="prev next"`}, "?cursor=next", false},
		{[]string{`<?a=1>; rel=next, <?a=2>; rel=next`}, "", true},
		{[]string{`<?a=1>; rel=next; anchor="/other"`}, "", true},
		{[]string{`<?a=1>; rel=next; rel=prev`}, "", true},
		{[]string{`<?a=1>; title="unterminated; rel=next`}, "", true},
		{[]string{`<?a=1>; rel=prev`}, "", false},
	}
	for n, c := range cases {
		got, e := ociNextLink(c.header, 16384)
		if (e != nil) != c.bad || got != c.want {
			t.Fatalf("case %d: next=%q error=%v", n, got, e)
		}
	}
}

func TestOCICatalogDoesNotAcceptIncompleteOrCyclicWalk(t *testing.T) {
	for _, mode := range []string{"cycle", "limit", "missing-page", "failed-page", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			var hits, foreignHits atomic.Int32
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
			defer foreign.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := hits.Add(1)
				if n > 1 && mode == "missing-page" {
					w.WriteHeader(404)
					return
				}
				if n > 1 && mode == "failed-page" {
					w.WriteHeader(503)
					return
				}
				target := "?cursor=next"
				if mode == "limit" {
					target = fmt.Sprintf("?cursor=%d", n)
				}
				if mode == "foreign" {
					target = foreign.URL + "/pages?cursor=next"
				}
				w.Header().Set("Link", "<"+target+">; rel=next")
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"name":"app","tags":[]}`)
			}))
			defer origin.Close()
			server := New(nil, nil, "")
			server.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			server.OCICatalogPages = 2
			repo := store.Repository{Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: origin.URL + "/v2/", Networks: []string{"127.0.0.1/32"}}}}
			client, e := server.newOCIRegistryClient(store.Identity{Tenant: "test-a"}, repo, "app")
			if e != nil {
				t.Fatal(e)
			}
			defer client.close()
			response, e := client.getCatalog(context.Background(), "app/tags/list", nil)
			if e != nil {
				t.Fatal(e)
			}
			g := ociGraphFill{server: server, client: client, ctx: context.Background(), repo: repo, image: "app", objects: map[string]store.Artifact{}, stack: map[string]bool{}}
			if _, e = g.catalog("tags/list", "", response); e == nil || hits.Load() > 2 || foreignHits.Load() != 0 {
				t.Fatalf("incomplete walk accepted or escaped: %v hits=%d foreign=%d", e, hits.Load(), foreignHits.Load())
			}
		})
	}
}

func FuzzOCINextLink(f *testing.F) {
	f.Add(`<?cursor=two>; rel="next"`)
	f.Add(`<https://cdn.example/pages?sig=a,b>; rel="next"; title="a,b"`)
	f.Add(`<?a=1>; rel=next, <?a=2>; rel=next`)
	f.Fuzz(func(t *testing.T, raw string) {
		next, e := ociNextLink([]string{raw}, 16384)
		if e == nil && next != "" {
			if len(next) > 16384 || !strings.Contains(raw, "<"+next+">") {
				t.Fatal("link parser escaped its bounded input")
			}
		}
	})
}

func TestOCIDownstreamPaginationParameters(t *testing.T) {
	for _, raw := range []string{"n=-1", "n=1&n=2", "last=", "n=%ZZ", "n=2147483648", "last=../escape"} {
		if _, e := parseOCIPage(raw, "tags/list", 100); e == nil {
			t.Fatalf("bad pagination accepted: %q", raw)
		}
	}
	page, e := parseOCIPage("n=0", "tags/list", 100)
	if e != nil || page.Size != 0 {
		t.Fatal("zero page size not accepted")
	}
	page, e = parseOCIPage("n=100000", "tags/list", 100)
	if e != nil || page.Size != 100 {
		t.Fatal("operator page ceiling not applied")
	}
}
