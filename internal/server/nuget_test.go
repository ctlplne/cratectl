// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/store"
)

func nugetNupkgFixture(t *testing.T, id, version string) ([]byte, []byte) {
	t.Helper()
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?><package><metadata><id>` + id + `</id><version>` + version + `</version><authors>cratectl fixture</authors><description>Owned inert package</description></metadata></package>`)
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, entry := range []struct {
		name string
		data []byte
	}{{id + ".nuspec", manifest}, {"content/owned.txt", []byte("Owned cratectl package fixture; never executed.\n")}} {
		w, e := z.Create(entry.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(entry.data); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes(), manifest
}

func nugetMultipart(t *testing.T, data []byte, extras int) ([]byte, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	p, e := w.CreateFormFile("ignored-field", "../../ignored.nupkg")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Write(data); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < extras; n++ {
		if e = w.WriteField("ignored", "Not package metadata."); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes(), w.FormDataContentType()
}

func TestNuGetCredentialIsScopedAndUnambiguous(t *testing.T) {
	apiKey, bearer := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for _, tc := range []struct {
		method, path string
		keys         []string
		want         string
		bad          bool
	}{
		{"PUT", "/nuget/owned/api/v2/package", []string{apiKey}, apiKey, false},
		{"PUT", "/nuget/owned/api/v2/package/", []string{apiKey}, apiKey, false},
		{"PUT", "/nuget/owned/api/v2/package", nil, "", true},
		{"PUT", "/nuget/owned/api/v2/package", []string{apiKey, apiKey}, "", true},
		{"PUT", "/nuget/owned/api/v2/package", []string{apiKey + "," + apiKey}, "", true},
		{"GET", "/nuget/owned/index.json", []string{apiKey}, bearer, false},
		{"PUT", "/api/v1/repositories", []string{apiKey}, bearer, false},
		{"PUT", "/npm/owned/api/v2/package", []string{apiKey}, bearer, false},
		{"POST", "/nuget/owned/api/v2/package", []string{apiKey}, bearer, false},
		{"DELETE", "/nuget/owned/api/v2/package/Owned.Package/1.0", []string{apiKey}, apiKey, false},
		{"POST", "/nuget/owned/api/v2/package/Owned.Package/1.0/", []string{apiKey}, apiKey, false},
		{"DELETE", "/nuget/owned/api/v2/package/Owned.Package/1.0", nil, "", true},
		{"POST", "/nuget/owned/api/v2/package/Owned.Package/1.0", []string{apiKey, apiKey}, "", true},
		{"DELETE", "/npm/owned/api/v2/package/Owned.Package/1.0", []string{apiKey}, bearer, false},
		{"DELETE", "/nuget/owned/api/v2/package/Owned.Package/1.0/extra", []string{apiKey}, bearer, false},
		{"GET", "/nuget/owned/api/v2/package/Owned.Package/1.0", []string{apiKey}, bearer, false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		for _, key := range tc.keys {
			r.Header.Add("X-NuGet-ApiKey", key)
		}
		got, e := requestCredential(r)
		if got != tc.want || (e != nil) != tc.bad {
			t.Fatal("credential scope or ambiguity changed", tc.method, tc.path)
		}
	}
}

func TestNuGetListingHTTPBoundary(t *testing.T) {
	s := New(nil, nil, "https://registry.example")
	for _, tc := range []struct {
		method, body string
		want         int
	}{
		{"GET", "", 405}, {"PUT", "", 405},
		{"DELETE", "unexpected", 400}, {"POST", "unexpected", 400},
	} {
		r := httptest.NewRequest(tc.method, "/nuget/owned/api/v2/package/Owned.Package/1.0", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		s.nuget(w, r, store.Identity{}, store.Repository{Name: "owned", Mode: "hosted"}, "api/v2/package/Owned.Package/1.0")
		if w.Code != tc.want {
			t.Fatal("listing method/body boundary", tc.method, w.Code)
		}
	}
}

func TestNuGetDiscoveryUsesConfiguredAuthority(t *testing.T) {
	s := New(nil, nil, "https://registry.example/base")
	for _, method := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(method, "http://poison.example/nuget/owned/index.json", nil)
		w := httptest.NewRecorder()
		s.nuget(w, r, store.Identity{}, store.Repository{Name: "owned", Mode: "hosted"}, "index.json")
		if w.Code != 200 || w.Header().Get("ETag") == "" {
			t.Fatal("discovery", w.Code)
		}
		if method == "HEAD" {
			if w.Body.Len() != 0 {
				t.Fatal("HEAD leaked response body")
			}
			continue
		}
		var document struct {
			Version   string              `json:"version"`
			Resources []map[string]string `json:"resources"`
		}
		if json.Unmarshal(w.Body.Bytes(), &document) != nil || document.Version != "3.0.0" || len(document.Resources) != 2 {
			t.Fatal("discovery resources")
		}
		for _, resource := range document.Resources {
			if !strings.HasPrefix(resource["@id"], "https://registry.example/base/nuget/owned/") {
				t.Fatal("request Host influenced discovery")
			}
		}
	}
	s.PublicURL = "https://registry.example/?credential=unsafe"
	w := httptest.NewRecorder()
	s.nuget(w, httptest.NewRequest("GET", "/", nil), store.Identity{}, store.Repository{Name: "owned", Mode: "hosted"}, "index.json")
	if w.Code != 503 {
		t.Fatal("invalid configured public URL accepted")
	}
}

func TestNuGetMalformedPublicationCannotCommit(t *testing.T) {
	b, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	s := New(nil, b, "https://localhost:38443") // No database: rejection must precede publication.
	valid, _ := nugetNupkgFixture(t, "Owned.Package", "1.0")
	for _, tc := range []struct {
		data  []byte
		extra int
	}{
		{[]byte("not a package"), 0},
		{valid, 128},
	} {
		body, contentType := nugetMultipart(t, tc.data, tc.extra)
		r := httptest.NewRequest("PUT", "/", bytes.NewReader(body)).WithContext(context.Background())
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		s.nugetPush(w, r, store.Identity{Tenant: "owned"}, store.Repository{Name: "owned", Mode: "hosted"})
		if w.Code != 400 {
			t.Fatal("malformed publication accepted", w.Code)
		}
	}
	body, contentType := nugetMultipart(t, valid, 0)
	for _, tc := range []struct {
		body  []byte
		limit int64
		code  int
	}{{body[:len(body)-8], 64 << 20, 400}, {body, 32, 413}, {append(append([]byte(nil), body...), bytes.Repeat([]byte{'x'}, (1<<20)+1)...), int64(len(valid)), 413}} {
		s.NuGetUploadBytes = tc.limit
		r := httptest.NewRequest("PUT", "/", bytes.NewReader(tc.body))
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		s.nugetPush(w, r, store.Identity{Tenant: "owned"}, store.Repository{Name: "owned", Mode: "hosted"})
		if w.Code != tc.code {
			t.Fatal("incomplete or oversized multipart publication accepted", w.Code, tc.code)
		}
	}
}
