// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/configfile"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestRepositoryAuthorityMismatchRefusesBeforeConnecting(t *testing.T) {
	directory := t.TempDir()
	token := filepath.Join(directory, "owned.token")
	if err := configfile.WriteNewPrivate(token, []byte("owned-test-only\n")); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "client.json")
	content, err := json.Marshal(configfile.Client{Version: 1, URL: "https://localhost:38443", TokenFile: token})
	if err != nil {
		t.Fatal(err)
	}
	if err := configfile.WriteNewPrivate(config, content); err != nil {
		t.Fatal(err)
	}
	r := &hostedRepository{configPath: config}
	remote, _, err := r.open(context.Background(), "cratectl-test", "https://127.0.0.1:38443")
	if remote != nil {
		remote.Close()
		t.Fatal("opened a client for a different authority")
	}
	if err == nil || !strings.Contains(err.Error(), "authority differs") {
		t.Fatalf("expected the authority decision before network access, got %v", err)
	}
}

func TestRepositoryUpdateAndDeleteKeepTheRetainedResource(t *testing.T) {
	r := &hostedRepository{}
	var update resource.UpdateResponse
	r.Update(context.Background(), resource.UpdateRequest{}, &update)
	if !update.Diagnostics.HasError() || update.Diagnostics.Errors()[0].Summary() != "Hosted repository settings require operator review" {
		t.Fatal("update did not require explicit reconciliation")
	}
	var deleteResponse resource.DeleteResponse
	r.Delete(context.Background(), resource.DeleteRequest{}, &deleteResponse)
	if !deleteResponse.Diagnostics.HasError() || deleteResponse.Diagnostics.Errors()[0].Summary() != "Repository retirement requires a cratectl operator" {
		t.Fatal("delete did not require explicit retirement")
	}
}
