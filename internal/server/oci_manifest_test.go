// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

const testOCIImage = "application/vnd.oci.image.manifest.v1+json"
const testOCIIndex = "application/vnd.oci.image.index.v1+json"

func ociFixture() map[string]any {
	return map[string]any{"schemaVersion": 2, "mediaType": testOCIImage, "config": map[string]any{"mediaType": "application/vnd.example.config", "size": 2, "digest": "sha256:" + crypt.Digest([]byte("{}"))}, "layers": []any{}}
}
func TestOCIManifestIdentity(t *testing.T) {
	data, _ := json.Marshal(ociFixture())
	m, e := parseOCIManifest(data, testOCIImage)
	if e != nil || len(m.Children) != 1 || m.ArtifactType != "application/vnd.example.config" {
		t.Fatalf("valid artifact: %+v %v", m, e)
	}
	if _, e = parseOCIManifest(data, testOCIIndex); e == nil {
		t.Fatal("accepted contradictory content type")
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing config":           func(m map[string]any) { delete(m, "config") },
		"case variant config":      func(m map[string]any) { m["Config"] = m["config"]; delete(m, "config") },
		"missing layers":           func(m map[string]any) { delete(m, "layers") },
		"null layers":              func(m map[string]any) { m["layers"] = nil },
		"mixed graphs":             func(m map[string]any) { m["manifests"] = []any{} },
		"missing size":             func(m map[string]any) { delete(m["config"].(map[string]any), "size") },
		"negative size":            func(m map[string]any) { m["config"].(map[string]any)["size"] = -1 },
		"fractional size":          func(m map[string]any) { m["config"].(map[string]any)["size"] = 1.5 },
		"missing descriptor media": func(m map[string]any) { delete(m["config"].(map[string]any), "mediaType") },
		"bad descriptor media":     func(m map[string]any) { m["config"].(map[string]any)["mediaType"] = "text/plain; charset=utf-8" },
		"wrong embedded bytes": func(m map[string]any) {
			m["config"].(map[string]any)["data"] = base64.StdEncoding.EncodeToString([]byte("xx"))
		},
		"wrong embedded size": func(m map[string]any) {
			m["config"].(map[string]any)["data"] = base64.StdEncoding.EncodeToString([]byte("{}"))
			m["config"].(map[string]any)["size"] = 1
		},
		"invalid artifact type": func(m map[string]any) { m["artifactType"] = "invalid" },
		"empty config without type": func(m map[string]any) {
			m["config"].(map[string]any)["mediaType"] = "application/vnd.oci.empty.v1+json"
		},
		"invalid annotation":   func(m map[string]any) { m["annotations"] = map[string]any{"key": 1} },
		"null subject":         func(m map[string]any) { m["subject"] = nil },
		"null annotation":      func(m map[string]any) { m["annotations"] = map[string]any{"key": nil} },
		"empty media field":    func(m map[string]any) { m["mediaType"] = "" },
		"empty artifact field": func(m map[string]any) { m["artifactType"] = "" },
		"empty platform":       func(m map[string]any) { m["config"].(map[string]any)["platform"] = map[string]any{} },
		"conflicting duplicate descriptor": func(m map[string]any) {
			m["layers"] = []any{map[string]any{"mediaType": "text/plain", "digest": m["config"].(map[string]any)["digest"], "size": 3}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := ociFixture()
			mutate(fixture)
			data, _ := json.Marshal(fixture)
			if _, e := parseOCIManifest(data, testOCIImage); e == nil {
				t.Fatal("accepted invalid graph")
			}
		})
	}
	fixture := ociFixture()
	fixture["config"].(map[string]any)["data"] = base64.StdEncoding.EncodeToString([]byte("{}"))
	fixture["config"].(map[string]any)["urls"] = []string{"https://unapproved.example/content"}
	fixture["future-extension"] = map[string]any{"opaque": true}
	fixture["subject"] = map[string]any{"mediaType": testOCIImage, "size": 123, "digest": "sha256:" + strings.Repeat("a", 64)}
	data, _ = json.Marshal(fixture)
	m, e = parseOCIManifest(data, testOCIImage)
	if e != nil || m.Subject == nil || len(m.metadata("example").References) != 1 {
		t.Fatalf("embedded content or weak subject: %+v %v", m, e)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"schemaVersion":2,"schemaVersion":2}`),
		[]byte(`{"schemaVersion":2,"a":{"x":1,"x":2}}`),
		append(append([]byte{}, data...), []byte(` {}`)...),
		[]byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)),
		[]byte("{\"bad\":\"\xff\"}"),
	} {
		if _, e := parseOCIManifest(invalid, testOCIImage); e == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func TestOCIIndexDescriptors(t *testing.T) {
	for _, media := range []string{testOCIIndex, "application/vnd.docker.distribution.manifest.list.v2+json"} {
		m, e := parseOCIManifest([]byte(`{"schemaVersion":2,"manifests":[]}`), media)
		if e != nil || len(m.Children) != 0 {
			t.Fatalf("empty index %s: %v", media, e)
		}
	}
	data := []byte(`{"schemaVersion":2,"mediaType":"` + testOCIIndex + `","manifests":[{"mediaType":"` + testOCIImage + `","digest":"sha256:` + strings.Repeat("a", 64) + `","size":42,"platform":{"architecture":"arm64","os":"linux"}}]}`)
	m, e := parseOCIManifest(data, testOCIIndex)
	if e != nil || len(m.Children) != 1 || m.Children[0].Kind != "manifests" {
		t.Fatalf("platform index: %+v %v", m, e)
	}
}

func TestOCIPathAndAccept(t *testing.T) {
	for _, image := range []string{"simple", "nested/manifests-subdir/blobs/uploads/name", "nested/tags/list", "nested/manifests/example", "nested/referrers/example"} {
		for _, test := range []struct{ suffix, operation, ref string }{
			{"/manifests/latest", "manifests", "latest"}, {"/blobs/sha256:abcdef", "blobs", "sha256:abcdef"}, {"/blobs/uploads/", "blobs/uploads", ""}, {"/blobs/uploads/opaque-id", "blobs/uploads", "opaque-id"}, {"/tags/list", "tags/list", ""}, {"/referrers/sha256:abcdef", "referrers", "sha256:abcdef"},
		} {
			got, op, ref := parseOCIPath(image + test.suffix)
			if got != image || op != test.operation || ref != test.ref {
				t.Fatalf("%s%s: %q %q %q", image, test.suffix, got, op, ref)
			}
		}
	}
	for _, test := range []struct {
		accept  string
		allowed bool
	}{
		{"", true}, {"*/*", true}, {"application/*", true}, {testOCIImage, true}, {testOCIIndex, false}, {testOCIImage + ";q=0, */*;q=1", false}, {testOCIImage + ";q=0.2, */*;q=0", true}, {testOCIImage + ";q=NaN", false}, {testOCIImage + ";q=2", false},
	} {
		if ociAcceptsMedia(test.accept, testOCIImage) != test.allowed {
			t.Fatalf("Accept %q", test.accept)
		}
	}
}

func TestOCIAcceptFieldLines(t *testing.T) {
	for _, test := range []struct {
		name   string
		fields []string
		allow  bool
	}{
		{"absent", nil, true},
		{"Docker then OCI", []string{"application/vnd.docker.distribution.manifest.v2+json", testOCIImage}, true},
		{"OCI then Docker", []string{testOCIImage, "application/vnd.docker.distribution.manifest.v2+json"}, true},
		{"exclude after wildcard", []string{"*/*", testOCIImage + ";q=0"}, false},
		{"exclude before wildcard", []string{testOCIImage + ";q=0", "*/*"}, false},
		{"positive before excluded wildcard", []string{testOCIImage + ";q=0.2", "*/*;q=0"}, true},
		{"unaccepted types", []string{testOCIIndex, "text/plain"}, false},
		{"too many lines", append([]string{testOCIImage}, make([]string, 64)...), false},
		{"combined byte limit", []string{testOCIImage, strings.Repeat(" ", 8192)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := http.Header{}
			for _, value := range test.fields {
				header.Add("Accept", value)
			}
			if actual := ociAcceptsMediaFields(header.Values("Accept"), testOCIImage); actual != test.allow {
				t.Fatalf("multiple Accept fields: allowed=%v; want %v", actual, test.allow)
			}
		})
	}
}

func FuzzOCIAcceptFieldLines(f *testing.F) {
	f.Add("application/vnd.docker.distribution.manifest.v2+json", testOCIImage)
	f.Add("*/*", testOCIImage+";q=0")
	f.Add(testOCIImage+";q=0.2", "application/*;q=0")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, first, second string) {
		forward := ociAcceptsMediaFields([]string{first, second}, testOCIImage)
		reverse := ociAcceptsMediaFields([]string{second, first}, testOCIImage)
		if forward != reverse {
			t.Fatal("field order changed accepted representations")
		}
		if len(first)+len(second)+1 > 8192 && forward {
			t.Fatal("oversized field list bypassed the byte budget")
		}
	})
}

func FuzzOCIManifest(f *testing.F) {
	data, _ := json.Marshal(ociFixture())
	f.Add(data)
	withURLs := ociFixture()
	withURLs["config"].(map[string]any)["urls"] = []string{"https://delivery.example/objects/config?signature=a%2Fb&order=two&order=one"}
	data, _ = json.Marshal(withURLs)
	f.Add(data)
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"` + testOCIIndex + `","manifests":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, e := parseOCIManifest(data, "")
		if e == nil {
			metadata := m.metadata("test/image")
			if len(metadata.References) > ociDescriptorLimit || !metadata.Validated {
				t.Fatal("unbounded graph")
			}
		}
	})
}
