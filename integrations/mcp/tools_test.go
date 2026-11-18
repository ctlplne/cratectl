// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPRegistryScopeAndExactToolProjection(t *testing.T) {
	const token = "owned-test-token"
	const tenant = "cratectl-owned"
	const repo = "cratectl-npm"
	const private = "owned-private-field"
	digest := strings.Repeat("f", 64)
	var denied, wrongTenant, revoked atomic.Bool
	var protectedReads atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("registry received an unscoped request")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/session" {
			if revoked.Load() {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, private)
				return
			}
			effectiveTenant := tenant
			if wrongTenant.Load() {
				effectiveTenant = "cratectl-other"
			}
			_, _ = fmt.Fprintf(w, `{"tenant":%q,"role":"reader","formats":["npm"],"actor":%q}`, effectiveTenant, private)
			return
		}
		protectedReads.Add(1)
		switch r.URL.Path {
		case managementRoot:
			if r.URL.Query().Get("limit") != "1" || r.URL.Query().Get("q") != "ordinary search" {
				t.Error("unexpected repository page query")
			}
			_, _ = fmt.Fprintf(w, `{"items":[{"name":%q,"format":"npm","mode":"hosted","access":"restricted","require_review":true,"settings":{"marker":%q}}],"limit":1,"next":"p1.owned","previous":""}`, repo, private)
		case managementRoot + "/" + repo + "/artifacts":
			if r.URL.Query().Get("metadata") != "omit" || r.URL.Query().Get("limit") != "1" {
				t.Error("metadata or page budget was missing")
			}
			_, _ = fmt.Fprintf(w, `{"items":[{"repository":%q,"path":"letters/a.tgz","digest":%q,"size":42,"media_type":"application/gzip","decision":"allowed","metadata":%q}],"limit":1,"next":"","previous":""}`, repo, digest, private)
		case managementRoot + "/" + repo + "/artifacts/reference":
			if denied.Load() {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, private)
				return
			}
			if r.URL.Query().Get("path") != "letters/a.tgz" {
				t.Error("unexpected retained path")
			}
			_, _ = fmt.Fprintf(w, `{"repository":%q,"path":"letters/a.tgz","digest":%q,"size":42,"media_type":"application/gzip","decision":"allowed","metadata":%q}`, repo, digest, private)
		default:
			t.Errorf("unexpected registry route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer origin.Close()
	configDir := t.TempDir()
	tokenPath := filepath.Join(configDir, "owned.token")
	caPath := filepath.Join(configDir, "owned-ca.pem")
	configPath := filepath.Join(configDir, "owned.json")
	encoded, err := json.Marshal(configfile.Client{Version: 1, URL: origin.URL, TokenFile: tokenPath, CAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	for destination, contents := range map[string][]byte{
		tokenPath:  []byte(token + "\n"),
		caPath:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}),
		configPath: encoded,
	} {
		if err := configfile.WriteNewPrivate(destination, contents); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b := &bridge{config: configPath, scope: scope{origin.URL, tenant}, slots: make(chan struct{}, 4)}
	server, peer := mcp.NewInMemoryTransports()
	serverSession, err := b.server().Connect(ctx, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "cratectl-owned-test", Version: "0"}, nil)
	session, err := c.Connect(ctx, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint ||
			tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("incorrect bounded read-only tool declaration")
		}
	}
	slices.Sort(names)
	if !reflect.DeepEqual(names, []string{"cratectl_get_artifact", "cratectl_get_repository", "cratectl_list_artifacts", "cratectl_list_repositories", "cratectl_session"}) {
		t.Fatalf("unexpected tool inventory %v", names)
	}
	call := func(name string, arguments any, expectedError string) string {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
		if err != nil || result == nil || result.IsError != (expectedError != "") {
			t.Fatalf("unexpected tool outcome %+v, %v", result, err)
		}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		if strings.Contains(body, token) || strings.Contains(body, private) || expectedError != "" && !strings.Contains(body, expectedError) {
			t.Fatal("missed safe tool status or projected private data")
		}
		return body
	}
	if result := call("cratectl_session", nil, ""); !strings.Contains(result, tenant) {
		t.Fatal("missing current tenant evidence")
	}
	if result := call("cratectl_list_repositories", map[string]any{"limit": 1, "search": "ordinary search"}, ""); !strings.Contains(result, "p1.owned") {
		t.Fatal("missing original page continuation")
	}
	if result := call("cratectl_list_artifacts", map[string]any{"repository": repo, "limit": 1}, ""); !strings.Contains(result, digest) {
		t.Fatal("missing exact artifact digest")
	}
	coordinate := map[string]any{"repository": repo, "path": "letters/a.tgz"}
	if result := call("cratectl_get_artifact", coordinate, ""); !strings.Contains(result, digest) || !strings.Contains(result, "allowed") {
		t.Fatal("missing current reference evidence")
	}
	denied.Store(true)
	call("cratectl_get_artifact", coordinate, "registry_denied")
	reads := protectedReads.Load()
	wrongTenant.Store(true)
	call("cratectl_get_artifact", coordinate, "registry_scope")
	wrongTenant.Store(false)
	revoked.Store(true)
	call("cratectl_get_artifact", coordinate, "registry_unauthenticated")
	call("cratectl_list_artifacts", map[string]any{"repository": repo, "limit": 51}, "invalid_page")
	if protectedReads.Load() != reads {
		t.Fatal("tenant scope or malformed input reached the protected route")
	}
}

func TestRegistryResultBudgetRefusesPartialData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxResponse+1))
	}))
	defer server.Close()
	var value identity
	err := get(context.Background(), server.Client(), "owned-test-token", server.URL, &value)
	if err == nil || !strings.Contains(err.Error(), "registry_response_limit") || value.Tenant != "" {
		t.Fatalf("oversized response produced a partial identity or incorrect status %v", err)
	}
}
