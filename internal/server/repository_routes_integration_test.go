//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestRepositoryNamesDoNotSelectNestedManagementRoutes(t *testing.T) {
	s, d, admin, _ := schemaServer(t)
	reader, _ := crypt.Token()
	other, _ := crypt.Token()
	for _, credential := range []struct{ tenant, actor, role, token string }{
		{"schema-http", "reader", "reader", reader},
		{"schema-other", "operator", "admin", other},
	} {
		if e := store.Provision(context.Background(), d.OwnerDSN, credential.tenant, credential.actor, credential.role, credential.token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	request := func(token, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "repository-name-"+crypt.Digest([]byte(method+"\x00"+path+"\x00"+body)))
		response := httptest.NewRecorder()
		s.ServeHTTP(response, r)
		return response
	}
	for _, name := range []string{"cache", "artifacts", "configuration", "state", "retention-policies"} {
		t.Run(name, func(t *testing.T) {
			created := request(admin, "POST", "/api/v1/repositories", `{"name":"`+name+`","format":"generic","settings":{"namespace_owners":{"private":"source"}}}`)
			if created.Code != 201 {
				t.Fatalf("create repository %s: %d %s", name, created.Code, created.Body.String())
			}
			path := "/api/v1/repositories/" + name
			for _, identity := range []struct {
				token    string
				settings bool
			}{{admin, true}, {reader, false}} {
				response := request(identity.token, "GET", path, "")
				var repository store.Repository
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &repository) != nil || repository.Name != name || repository.Format != "generic" || repository.SourceRevision != 0 {
					t.Errorf("repository detail %s: %d %s", name, response.Code, response.Body.String())
					continue
				}
				if (len(repository.Settings.NamespaceOwners) > 0) != identity.settings {
					t.Error("repository detail settings did not follow current role")
				}
			}
			if response := request(other, "GET", path, ""); response.Code != 404 {
				t.Errorf("other tenant detail: %d", response.Code)
			}
			if response := request(reader, "GET", path+"/artifacts?limit=1", ""); response.Code != 200 || !strings.Contains(response.Body.String(), `"items":[]`) {
				t.Errorf("nested artifact list: %d %s", response.Code, response.Body.String())
			}
			if response := request(admin, "GET", path+"/cache", ""); response.Code != 400 || !strings.Contains(response.Body.String(), "invalid_path") {
				t.Errorf("nested cache inspection must require a path: %d", response.Code)
			}
			if response := request(admin, "GET", path+"?path=content", ""); response.Code != 400 || !strings.Contains(response.Body.String(), "invalid_repository") {
				t.Errorf("detail query must not become cache inspection: %d", response.Code)
			}
		})
	}
}
