// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"ctlplne.dev/cratectl/internal/store"
)

func TestNuGetSearchInputIsBoundedAndExplicit(t *testing.T) {
	for _, query := range []string{"take=0", "take=1001", "skip=-1", "skip=100001", "q=a&q=b", "prerelease=1", "semVerLevel=invalid", "q=%zz", "q=%00", "q=" + strings.Repeat("x", 257), "packageType=Unsupported"} {
		if _, e := parseNuGetSearch(httptest.NewRequest("GET", "/query?"+query, nil)); e == nil {
			t.Fatal("invalid search accepted", query)
		}
	}
	q, e := parseNuGetSearch(httptest.NewRequest("GET", "/query?q=Owned%25&skip=2&take=3&prerelease=true&semVerLevel=2.0.0", nil))
	if e != nil || q.Query != "Owned%" || q.Skip != 2 || q.Take != 3 || !q.Prerelease || !q.SemVer2 {
		t.Fatal(q, e)
	}
}

func TestNuGetRegistrationPreservesDeclaredRangesAndListing(t *testing.T) {
	raw := []byte(`<package><metadata><id>Owned.Package</id><version>1.0+Owned</version><requireLicenseAcceptance>TrUe</requireLicenseAcceptance><projectUrl>javascript:unused()</projectUrl><dependencies><group targetFramework="net10.0"><dependency id="Owned.Dep" version="1.2*"/><dependency id="Other.Dep" version="*"/></group></dependencies></metadata></package>`)
	listed := false
	m := store.NuGetPackage{ID: "Owned.Package", IDKey: "owned.package", IDProfile: nuget.IDKeyProfile, RawVersion: "1.0+Owned", VersionKey: "1.0.0", NuspecPath: "Owned.Package.nuspec", Nuspec: raw, NuspecSHA256: crypt.Digest(raw), Validated: true, Listed: &listed}
	metadata, _ := json.Marshal(m)
	a := store.Artifact{Path: store.NuGetPath(m.IDKey, m.VersionKey), Digest: strings.Repeat("a", 64), Size: 123, MediaType: "application/octet-stream", Metadata: metadata, Created: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)}
	key, catalog, entry, e := registrationEntry(context.Background(), "https://registry.example/nuget/owned/", a)
	if e != nil || key != "1.0.0" || catalog["version"] != "1.0.0+Owned" || catalog["listed"] != false || catalog["published"] != "1900-01-01T00:00:00Z" || catalog["requireLicenseAcceptance"] != true || catalog["projectUrl"] != nil || entry["catalogEntry"] == nil {
		t.Fatal(catalog, e)
	}
	groups := catalog["dependencyGroups"].([]map[string]any)
	deps := groups[0]["dependencies"].([]map[string]string)
	if groups[0]["targetFramework"] != "net10.0" || deps[0]["range"] != "1.2*" || deps[1]["range"] != "[0.0.0, )" {
		t.Fatal("dependency semantics widened", groups)
	}
}

func TestNuGetRegistrationRemovesOnlyEquivalentDependencies(t *testing.T) {
	raw := []byte(`<package><metadata><id>Owned.Package</id><version>1</version><dependencies><group><dependency id="Owned.A" version="1"/><dependency id="owned.a" version="1.0.0"/><dependency id="Owned.A" version="2"/></group><group/></dependencies></metadata></package>`)
	m := store.NuGetPackage{ID: "Owned.Package", IDKey: "owned.package", IDProfile: nuget.IDKeyProfile, RawVersion: "1", VersionKey: "1.0.0", NuspecPath: "Owned.Package.nuspec", Nuspec: raw, NuspecSHA256: crypt.Digest(raw), Validated: true}
	metadata, _ := json.Marshal(m)
	a := store.Artifact{Path: store.NuGetPath(m.IDKey, m.VersionKey), Digest: strings.Repeat("a", 64), Size: 123, MediaType: "application/octet-stream", Metadata: metadata}
	_, catalog, _, e := registrationEntry(context.Background(), "https://registry.example/nuget/owned/", a)
	if e != nil {
		t.Fatal(e)
	}
	groups := catalog["dependencyGroups"].([]map[string]any)
	deps := groups[0]["dependencies"].([]map[string]string)
	if len(groups) != 2 || len(deps) != 2 || deps[0]["id"] != "Owned.A" || deps[0]["range"] != "1" || deps[1]["range"] != "2" {
		t.Fatal("first declaration, dependency set or empty group changed", groups)
	}
}

func TestNuGetRegistrationGzipRepresentationHTTP(t *testing.T) {
	s := New(nil, nil, "https://registry.example")
	value := map[string]any{"count": 0, "items": []any{}}
	get := httptest.NewRecorder()
	s.nugetGzipJSON(get, httptest.NewRequest("GET", "/", nil), value)
	reader, e := gzip.NewReader(bytes.NewReader(get.Body.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(reader)
	reader.Close()
	if e != nil || !json.Valid(raw) || get.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("invalid representation", e)
	}
	for _, method := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "/", nil)
		s.nugetGzipJSON(w, r, value)
		if w.Code != 200 || w.Header().Get("ETag") != get.Header().Get("ETag") || method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("nondeterministic gzip or HEAD", w.Code)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("If-None-Match", get.Header().Get("ETag"))
	s.nugetGzipJSON(w, r, value)
	if w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal("conditional registration", w.Code)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Range", "bytes=1-7")
	s.nugetGzipJSON(w, r, value)
	if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), get.Body.Bytes()[1:8]) {
		t.Fatal("range over compressed representation", w.Code)
	}
	s.NativeMetadataBytes = 1
	w = httptest.NewRecorder()
	s.nugetGzipJSON(w, httptest.NewRequest("GET", "/", nil), value)
	if w.Code != 503 || w.Header().Get("Content-Encoding") != "" {
		t.Fatal("overbudget partially emitted", w.Code)
	}
}
