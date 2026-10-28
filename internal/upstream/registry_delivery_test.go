// SPDX-License-Identifier: BUSL-1.1
package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegistryDeliveryNetworkErrorDoesNotExposeSignedURI(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	raw := origin.URL + "/objects/layer?signature=owned-private-query"
	origin.Close()
	endpoint, e := New(Config{URL: origin.URL + "/objects/", Networks: []string{"127.0.0.1/32"}, AllowSignedQuery: true}, "", "127.0.0.1/32")
	if e != nil {
		t.Fatal(e)
	}
	defer endpoint.Close()
	if endpoint.AllowsURL(raw) {
		t.Fatal("ordinary durable URL validation was widened")
	}
	if _, e = endpoint.GetRegistryDelivery(context.Background(), raw, nil); e == nil || strings.Contains(e.Error(), "owned-private-query") {
		t.Fatalf("delivery error exposed signed URI: %v", e)
	}
}

func FuzzRegistryDeliveryURL(f *testing.F) {
	for _, raw := range []string{"https://cdn.example/objects/a?signature=owned%2Fvalue&b=2&a=1", "https://cdn.example/objects/%2e%2e/private?signature=owned", "https://foreign.example/objects/layer", "https://cdn.example/objects/?signature=owned", "https://cdn.example/objects/layer?signature=%ZZ"} {
		f.Add(raw)
	}
	endpoint, e := New(Config{URL: "https://cdn.example/objects/", Networks: []string{"0.0.0.0/0"}, AllowSignedQuery: true}, "")
	if e != nil {
		f.Fatal(e)
	}
	defer endpoint.Close()
	f.Fuzz(func(t *testing.T, raw string) {
		if endpoint.RegistryDeliveryPriority(raw) == 0 {
			return
		}
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host != "cdn.example" || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, "/objects/") || (u.Path != "/objects/" && !SafePath(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/objects/"), "/"))) {
			t.Fatal("delivery escaped path authority")
		}
		if _, e = url.ParseQuery(u.RawQuery); e != nil || len(u.RawQuery) > 8192 {
			t.Fatal("unbounded or malformed signed query accepted")
		}
		if u.RawQuery != "" && endpoint.AllowsURL(raw) {
			t.Fatal("signed ephemeral URL became a durable package binding")
		}
	})
}

func TestRegistryDeliveryExactConfiguredPath(t *testing.T) {
	endpoint, e := New(Config{URL: "https://cdn.example/download", Networks: []string{"0.0.0.0/0"}, AllowSignedQuery: true}, "")
	if e != nil {
		t.Fatal(e)
	}
	defer endpoint.Close()
	for _, raw := range []string{"https://cdn.example/download?signature=owned", "https://cdn.example/download/object?signature=owned"} {
		if endpoint.RegistryDeliveryPriority(raw) == 0 {
			t.Fatal("approved exact/prefix delivery rejected")
		}
	}
	if endpoint.RegistryDeliveryPriority("https://cdn.example/downloadevil?signature=owned") != 0 {
		t.Fatal("adjacent path escaped delivery scope")
	}
}
