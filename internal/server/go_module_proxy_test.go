// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func goOriginStandIn(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:38443")
	if e != nil {
		t.Fatal("bind owned cratectl Go origin stand-in", e)
	}
	s := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func goOriginBytes(t *testing.T) (gomodule.Coordinate, map[string][]byte) {
	t.Helper()
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/bundle", Version: "v1.0.0"}
	mod := []byte("module " + c.Module + "\n\ngo 1.26.0\n")
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, file := range []struct {
		name string
		body []byte
	}{{"go.mod", mod}, {"assets/inert.txt", []byte("Owned inert stand-in; never execute package contents.\n")}} {
		w, e := z.Create(c.Module + "@" + c.Version + "/" + file.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(file.body); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return c, map[string][]byte{"zip": b.Bytes(), "mod": mod, "info": []byte("{\n \"Version\":\"v1.0.0\", \"Time\":\"2026-01-02T03:04:05Z\", \"Origin\":{\"opaque\":true}\n}\n")}
}

func goOriginFixture(t *testing.T, url string, c gomodule.Coordinate) (*Server, store.Identity, store.Repository, store.Retrieval) {
	t.Helper()
	objects, e := blob.New(t.TempDir(), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	s := New(nil, objects, "")
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	s.UpstreamCredentials["owned/standin"] = UpstreamCredential{Value: "owned-origin-token", AllowedURL: url + "/go/source/"}
	r := store.Repository{Name: "source", Format: "go", Mode: "proxy", SourceRevision: 17, Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: url + "/go/source/", Networks: []string{"127.0.0.1/32"}, CredentialRef: "standin"}, Cache: store.CacheSettings{FreshSeconds: 60, StaleSeconds: 40}}}
	l := store.Retrieval{Repository: r.Name, Path: c.Prefix() + ".zip", SourceRevision: r.SourceRevision, ETag: "old-zip-validator", Modified: "old-zip-modified"}
	return s, store.Identity{Tenant: "owned"}, r, l
}

func TestGoModuleOriginStagesExactCompleteBundleAndStrictestCachePolicy(t *testing.T) {
	c, files := goOriginBytes(t)
	var calls atomic.Int32
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		kind := []string{"info", "mod", "zip"}[min(n, 2)]
		if n >= 3 || r.Method != "GET" || r.URL.Path != "/go/source/"+c.Prefix()+"."+kind || r.Header.Get("Authorization") != "Bearer owned-origin-token" || r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("origin request escaped exact source/credential/full-response authority")
			w.WriteHeader(400)
			return
		}
		switch kind {
		case "info":
			w.Header().Set("Cache-Control", "max-age=12")
		case "mod":
			w.Header().Set("Cache-Control", "max-age=7, must-revalidate")
		case "zip":
			w.Header().Set("Cache-Control", "max-age=20")
		}
		w.Write(files[kind])
	}))
	s, i, r, l := goOriginFixture(t, origin.URL, c)
	result, e := s.fetchGoModuleBundle(context.Background(), i, r, l)
	if e != nil || result.Status != 200 || result.Object == nil || result.GoModule == nil || len(result.GoModule.Objects) != 3 || calls.Load() != 3 || result.FreshSeconds != 7 || result.StaleSeconds != 0 || result.ETag != "" || result.Modified != "" {
		t.Fatal("complete source bundle/cache policy", e, calls.Load(), result.FreshSeconds, result.StaleSeconds)
	}
	for _, a := range result.GoModule.Objects {
		m, e := store.ValidateGoModuleArtifact(a)
		if e != nil || m.Module != c.Module || m.Version != c.Version {
			t.Fatal("bundle metadata not bound to canonical coordinate", e)
		}
		f, e := s.Blobs.OpenVerified(context.Background(), i.Tenant, a.Digest, a.Size)
		if e != nil {
			t.Fatal("result precedes durable verified object", e)
		}
		data, e := io.ReadAll(f)
		f.Close()
		kind := strings.TrimPrefix(strings.TrimPrefix(a.Path, c.Prefix()), ".")
		if e != nil || !bytes.Equal(data, files[kind]) {
			t.Fatal("origin bytes were synthesized or changed", kind, e)
		}
		if kind == "zip" && (a.Digest != result.Object.Digest || a.Size != result.Object.Size || !bytes.Equal(a.Metadata, result.Metadata)) {
			t.Fatal("common retrieval root differs from validated ZIP")
		}
	}
}

func TestGoModuleOriginRejectsIncompleteUntrustedAndOversizedResponses(t *testing.T) {
	for _, attack := range []string{"missing-info", "missing-mod", "missing-zip", "gone-mod", "conditional-304", "partial", "compressed", "duplicate-encoding", "duplicate-validator", "large-validator", "content-range", "no-store", "second-no-store", "info-version", "info-duplicate", "info-budget", "info-chunk-budget", "mod-budget", "mod-mismatch", "zip-byte-budget", "zip-chunk-budget", "zip-expansion-budget", "zip-directory-budget", "zip-file-budget", "zip-corrupt", "short-body", "denied", "server-failure", "redirect-path", "redirect-authority"} {
		t.Run(attack, func(t *testing.T) {
			c, files := goOriginBytes(t)
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if !strings.HasPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".") {
					t.Error("redirect escaped configured source path")
					w.WriteHeader(403)
					return
				}
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				data := files[kind]
				if attack == "missing-"+kind || attack == "gone-mod" && kind == "mod" {
					status := 404
					if attack == "gone-mod" {
						status = 410
					}
					w.WriteHeader(status)
					return
				}
				if kind == "info" {
					switch attack {
					case "conditional-304":
						w.WriteHeader(304)
						return
					case "partial":
						w.WriteHeader(206)
						return
					case "compressed":
						w.Header().Set("Content-Encoding", "gzip")
					case "duplicate-encoding":
						w.Header().Add("Content-Encoding", "identity")
						w.Header().Add("Content-Encoding", "gzip")
					case "duplicate-validator":
						w.Header().Add("ETag", "one")
						w.Header().Add("ETag", "two")
					case "large-validator":
						w.Header().Set("ETag", strings.Repeat("a", 1025))
					case "content-range":
						w.Header().Set("Content-Range", "bytes 0-1/2")
					case "no-store":
						w.Header().Set("Cache-Control", "no-store")
					case "second-no-store":
						w.Header().Add("Cache-Control", "max-age=60")
						w.Header().Add("Cache-Control", "no-store")
					case "info-version":
						data = []byte(`{"Version":"v1.1.0"}`)
					case "info-duplicate":
						data = []byte(`{"Version":"v1.0.0","Version":"v1.0.0"}`)
					case "info-budget", "info-chunk-budget":
						data = bytes.Repeat([]byte(" "), 129)
					case "denied":
						w.WriteHeader(403)
						return
					case "server-failure":
						w.WriteHeader(503)
						return
					case "redirect-path":
						w.Header().Set("Location", "/private/outside")
						w.WriteHeader(302)
						return
					case "redirect-authority":
						w.Header().Set("Location", "http://127.0.0.1:35432/credential-leak")
						w.WriteHeader(302)
						return
					}
				}
				if kind == "mod" {
					switch attack {
					case "mod-budget":
						data = bytes.Repeat([]byte(" "), 129)
					case "mod-mismatch":
						data = append(bytes.Clone(data), []byte("// differs from ZIP\n")...)
					}
				}
				if kind == "zip" && attack == "zip-corrupt" {
					data = data[:len(data)/2]
				}
				if kind == "zip" && attack == "short-body" {
					w.Header().Set("Content-Length", "999999")
				}
				if kind == "info" && attack == "info-chunk-budget" || kind == "zip" && attack == "zip-chunk-budget" {
					w.(http.Flusher).Flush()
				}
				w.Write(data)
			}))
			s, i, r, l := goOriginFixture(t, origin.URL, c)
			switch attack {
			case "info-budget", "info-chunk-budget", "mod-budget":
				s.NativeMetadataBytes = 128
			case "zip-byte-budget", "zip-chunk-budget":
				s.GoModuleUploadBytes = int64(len(files["zip"]) - 1)
			case "zip-expansion-budget":
				s.GoModuleExpandedBytes = 1
			case "zip-directory-budget":
				s.GoModuleDirectoryBytes = 1
			case "zip-file-budget":
				s.GoModuleFileLimit = 1
			}
			result, e := s.fetchGoModuleBundle(context.Background(), i, r, l)
			if e == nil || result.GoModule != nil || result.Object != nil || len(result.Metadata) != 0 || result.Status != 0 {
				t.Fatal("failed intake returned a publication-shaped bundle", e)
			}
			if errors.Is(e, errGoModuleOriginMissing) != (attack == "missing-info") {
				t.Fatal("partial/denied/damaged bundle authorized absence fallback", e)
			}
			if (attack == "redirect-path" || attack == "redirect-authority") && (!errors.Is(e, upstream.ErrRedirect) || calls.Load() != 1) {
				t.Fatal("source redirect authority was not enforced", e, calls.Load())
			}
		})
	}
}

func TestGoModuleOriginRetainsNoCacheAndVaryAcrossMultipleHeaders(t *testing.T) {
	for _, header := range []string{"Cache-Control", "Vary"} {
		t.Run(header, func(t *testing.T) {
			c, files := goOriginBytes(t)
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				if kind == "mod" {
					if header == "Cache-Control" {
						w.Header().Add(header, "max-age=60")
						w.Header().Add(header, "no-cache")
					} else {
						w.Header().Add(header, "Accept")
						w.Header().Add(header, "*")
					}
				}
				w.Write(files[kind])
			}))
			s, i, r, l := goOriginFixture(t, origin.URL, c)
			result, e := s.fetchGoModuleBundle(context.Background(), i, r, l)
			if e != nil || result.FreshSeconds != 0 || result.StaleSeconds != 0 {
				t.Fatal("cache directive disappeared behind another header", e, result.FreshSeconds, result.StaleSeconds)
			}
		})
	}
}

func TestGoModuleOriginCancelsTransferAndRejectsInvalidAuthorityBeforeNetwork(t *testing.T) {
	c, _ := goOriginBytes(t)
	var calls atomic.Int32
	arrived := make(chan struct{})
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(arrived)
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	s, i, r, l := goOriginFixture(t, origin.URL, c)
	for _, attack := range []string{"checksum", "tenant-credential", "credential-path", "source-epoch", "repository", "not-zip", "network"} {
		t.Run(attack, func(t *testing.T) {
			repo, identity, lease := r, i, l
			switch attack {
			case "checksum":
				repo.Settings.Cache.RequireChecksum = true
			case "tenant-credential":
				identity.Tenant = "other"
			case "credential-path":
				config := *repo.Settings.Upstream
				config.URL = origin.URL + "/private/"
				repo.Settings.Upstream = &config
			case "source-epoch":
				lease.SourceRevision--
			case "repository":
				lease.Repository = "other"
			case "not-zip":
				lease.Path = c.Prefix() + ".mod"
			case "network":
				s.PrivateUpstreamNetworks = nil
				defer func() { s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"} }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, e := s.fetchGoModuleBundle(ctx, identity, repo, lease)
			if e == nil || result.GoModule != nil || calls.Load() != 0 || attack == "checksum" && !errors.Is(e, errGoModuleChecksumRequired) {
				t.Fatal("invalid authority/checksum policy reached origin", attack, e, calls.Load())
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result store.RetrievalResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, e := s.fetchGoModuleBundle(ctx, i, r, l)
		done <- outcome{result, e}
	}()
	select {
	case <-arrived:
	case out := <-done:
		t.Fatal("transfer stopped before reaching owned cancellation stand-in", out.err)
	case <-time.After(3 * time.Second):
		t.Fatal("owned cancellation stand-in was not reached")
	}
	cancel()
	select {
	case out := <-done:
		if !errors.Is(out.err, context.Canceled) || out.result.GoModule != nil || calls.Load() != 1 {
			t.Fatal("cancellation produced a completed bundle", out.err, calls.Load())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled transfer did not stop within its test bound")
	}
}

func TestGoModuleProxyPublicRouteRemainsClosed(t *testing.T) {
	s := New(nil, nil, "")
	w := httptest.NewRecorder()
	p := "go.cratectl.invalid/owned/@v/v1.0.0.info"
	s.goModule(w, httptest.NewRequest("GET", "/go/source/"+p, nil), store.Identity{}, store.Repository{Name: "source", Format: "go", Mode: "proxy"}, p)
	if w.Code != 405 {
		t.Fatal("internal fetch foundation enabled incomplete public proxy mode", w.Code)
	}
}
