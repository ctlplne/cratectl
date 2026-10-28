// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"ctlplne.dev/cratectl/internal/upstream"
	"testing"
)

func TestPrivateCredentialAuthority(t *testing.T) {
	s := New(nil, nil, "https://localhost")
	s.UpstreamCredentials["tenant-a/source"] = UpstreamCredential{Value: "owned-test-value", AllowedURL: "https://registry.invalid/allowed/"}
	valid := upstream.Config{URL: "https://registry.invalid/allowed/pkg/", CredentialRef: "source"}
	if v, e := s.credential("tenant-a", valid); e != nil || v != "owned-test-value" {
		t.Fatal("configured authority was rejected")
	}
	if _, e := s.credential("tenant-b", valid); e == nil {
		t.Fatal("credential crossed tenants")
	}
	for _, target := range []string{"https://other.invalid/allowed/", "https://registry.invalid/allowed-collision/", "http://registry.invalid/allowed/"} {
		invalid := valid
		invalid.URL = target
		if _, e := s.credential("tenant-a", invalid); e == nil {
			t.Fatal("credential escaped approved destination")
		}
	}
	invalid := valid
	invalid.Authentication = "basic"
	if _, e := s.credential("tenant-a", invalid); e == nil {
		t.Fatal("credential authentication scheme changed")
	}
}

func TestManagementRejectsCredentialValuesInRepositoryConfig(t *testing.T) {
	var repository struct {
		Settings struct {
			Upstream upstream.Config `json:"upstream"`
		} `json:"settings"`
	}
	if decodeManagement([]byte(`{"settings":{"upstream":{"url":"https://registry.invalid/","networks":["0.0.0.0/0"],"value":"accidental-private-value"}}}`), &repository) {
		t.Fatal("unknown private credential value was silently accepted into public configuration")
	}
	if decodeManagement([]byte(`{} {}`), &repository) {
		t.Fatal("multiple management objects accepted")
	}
}
