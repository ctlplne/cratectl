//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func publishNativeLifecycleFixture(t *testing.T, s *Server, token, repo, format string, retained ...[]byte) (string, []byte, *httptest.ResponseRecorder) {
	t.Helper()
	request := lifecycleHTTP(t, s, token)
	switch format {
	case "npm":
		data := npmArchiveFixture(t, []npmArchiveEntry{{name: "package/package.json", body: `{"name":"lifecycle-pkg","version":"1.0.0"}`}, {name: "package/index.js", body: "module.exports = 42;"}})
		if len(retained) > 0 {
			data = retained[0]
		}
		doc := map[string]any{"name": "lifecycle-pkg", "versions": map[string]any{"1.0.0": map[string]string{"name": "lifecycle-pkg", "version": "1.0.0"}}, "dist-tags": map[string]string{"latest": "1.0.0"}, "_attachments": map[string]any{"lifecycle-pkg-1.0.0.tgz": map[string]any{"data": base64.StdEncoding.EncodeToString(data), "length": len(data)}}}
		return store.NPMPath("lifecycle-pkg", "1.0.0"), data, request("PUT", "/npm/"+repo+"/lifecycle-pkg", doc, "")
	case "pypi":
		filename := "pkg-1.0-py3-none-any.whl"
		data := pythonWheelFixture(t, "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\n\n", nil)
		if len(retained) > 0 {
			data = retained[0]
		}
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if e := writer.WriteField("name", "pkg"); e != nil {
			t.Fatal(e)
		}
		if e := writer.WriteField("version", "1.0"); e != nil {
			t.Fatal(e)
		}
		part, e := writer.CreateFormFile("content", filename)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = part.Write(data); e != nil {
			t.Fatal(e)
		}
		if e = writer.Close(); e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest("POST", "/pypi/"+repo+"/", &body)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return filename, data, w
	default:
		path, data := "owned/package.bin", "owned immutable bytes"
		if format == "maven" {
			path = "org/example/owned/1.0/owned-1.0.jar"
			mavenPut(t, s, token, repo, "org/example/owned/1.0/owned-1.0.pom", "<project><groupId>org.example</groupId><artifactId>owned</artifactId><version>1.0</version></project>")
		}
		return path, []byte(data), mavenHTTP(t, s, token, "PUT", "/r/"+repo+"/"+path, data)
	}
}

func TestMaterializedNativeHTTPMetadataRetirementAndVerifiedRestore(t *testing.T) {
	for _, format := range []string{"generic", "maven", "npm", "pypi"} {
		t.Run(format, func(t *testing.T) {
			s, _, token, admin := schemaServer(t)
			request := lifecycleHTTP(t, s, token)
			mavenRepositories(t, s, admin, store.Repository{Name: "first", Format: format}, store.Repository{Name: "second", Format: format}, store.Repository{Name: "combined", Format: format, Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}})
			path, raw, w := publishNativeLifecycleFixture(t, s, token, "first", format)
			if w.Code != 201 && w.Code != 200 {
				t.Fatal("native publish", w.Code, w.Body.String())
			}
			if _, _, w = publishNativeLifecycleFixture(t, s, token, "second", format, raw); w.Code != 201 && w.Code != 200 {
				t.Fatal("lower-source publish", w.Code, w.Body.String())
			}
			a, e := s.DB.Artifact(context.Background(), admin, "first", path)
			if e != nil {
				t.Fatal(e)
			}
			metadata, marker := "", ""
			download := func(repo string) string { return "/r/" + repo + "/" + path }
			switch format {
			case "maven":
				metadata, marker = "/r/combined/org/example/owned/maven-metadata.xml", "<version>1.0</version>"
			case "npm":
				metadata, marker = "/npm/combined/lifecycle-pkg", `"1.0.0"`
				download = func(repo string) string { return "/npm/" + repo + "/" + path }
			case "pypi":
				metadata, marker = "/pypi/combined/simple/pkg/", path
				download = func(repo string) string {
					return "/pypi/" + repo + "/files/" + repo + "/hosted/" + a.Digest + "/" + path
				}
			}
			if metadata != "" {
				if w = request("GET", metadata, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), marker) {
					t.Fatal("initial native metadata", w.Code, w.Body.String())
				}
			}
			api := "/api/v1/repositories/first/artifacts/lifecycle"
			input := store.ArtifactStateRequest{Path: path, Digest: a.Digest, Action: "delete", Reason: "retire exact native reference"}
			if w = request("PUT", api, input, "delete-native-object"); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if w = request("GET", download("first"), nil, ""); w.Code != 404 {
				t.Fatal("native read ignored tombstone", w.Code, w.Body.String())
			}
			if _, _, w = publishNativeLifecycleFixture(t, s, token, "first", format, raw); w.Code != 404 || !strings.Contains(w.Body.String(), "artifact_deleted") {
				t.Fatal("native publication resurrected retired bytes", w.Code, w.Body.String())
			}
			if format != "pypi" {
				if w = request("GET", download("combined"), nil, ""); w.Code == 200 {
					t.Fatal("group silently resurrected lower source", w.Code)
				}
			} else {
				if w = request("GET", strings.Replace(download("second"), "/pypi/second/", "/pypi/combined/", 1), nil, ""); w.Code == 200 {
					t.Fatal("pinned lower-source URL bypassed retired precedence", w.Code)
				}
			}
			if format == "npm" {
				if w = request("GET", "/npm/combined/lifecycle-pkg/-/cratectl/second/hosted/1.0.0.tgz", nil, ""); w.Code == 200 {
					t.Fatal("pinned npm lower-source URL bypassed retired precedence", w.Code)
				}
			}
			if w = request("GET", download("second"), nil, ""); w.Code != 200 {
				t.Fatal("local retirement became global digest denial", w.Code, w.Body.String())
			}
			if metadata != "" {
				if w = request("GET", metadata, nil, ""); w.Code != 200 && w.Code != 404 || strings.Contains(w.Body.String(), marker) {
					t.Fatal("native metadata advertised retired first-source content", w.Code, w.Body.String())
				}
			}
			// Changes to native tags/yanks while bytes are retained survive restore.
			if format == "npm" {
				if w = request("DELETE", "/npm/first/-/package/lifecycle-pkg/dist-tags/latest", nil, ""); w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
			}
			if format == "pypi" {
				if w = request("PUT", "/api/v1/repositories/first/yanks", map[string]any{"filename": path, "yanked": true, "reason": "retain native yank"}, "yank-retired-native"); w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
			}
			object, e := s.Blobs.Open(admin.Tenant, a.Digest)
			if e != nil {
				t.Fatal(e)
			}
			name := object.Name()
			object.Close()
			if e = os.WriteFile(name, bytes.Repeat([]byte{'x'}, len(raw)), 0600); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { _ = os.WriteFile(name, raw, 0600) })
			input.Action, input.ExpectedRevision = "restore", 1
			if w = request("PUT", api, input, "restore-native-object"); w.Code != 503 || !strings.Contains(w.Body.String(), "integrity_failure") {
				t.Fatal("corrupt CAS bytes restored", w.Code, w.Body.String())
			}
			if state, e := s.DB.ArtifactState(context.Background(), admin, "first", path); e != nil || !state.Deleted || state.Revision != 1 {
				t.Fatal("failed verification committed a transition", state, e)
			}
			if e = os.WriteFile(name, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if w = request("PUT", api, input, "restore-native-object"); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if w = request("GET", download("first"), nil, ""); w.Code != 200 || crypt.Digest(w.Body.Bytes()) != a.Digest {
				t.Fatal("restored bytes differ", w.Code)
			}
			if metadata != "" {
				if w = request("GET", metadata, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), marker) {
					t.Fatal("restored native metadata missing", w.Code, w.Body.String())
				}
			}
			if format == "npm" {
				w = request("GET", "/npm/first/lifecycle-pkg", nil, "")
				var doc struct {
					Tags map[string]string `json:"dist-tags"`
				}
				if e := json.Unmarshal(w.Body.Bytes(), &doc); w.Code != 200 || e != nil || len(doc.Tags) != 0 {
					t.Fatal("restore resurrected an explicitly removed npm tag", w.Code, w.Body.String(), e)
				}
			}
			if format == "pypi" {
				if w = request("GET", metadata, nil, ""); !strings.Contains(w.Body.String(), `data-yanked="retain native yank"`) {
					t.Fatal("restore lost native yank", w.Body.String())
				}
			}
		})
	}
}
