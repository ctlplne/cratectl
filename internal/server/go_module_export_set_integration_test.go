//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleExportSetPreviewUsesCommonStoreAndCreatesNoSession(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	ctx := context.Background()
	const repo = "set-preview"
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "go", RequireReview: true, Access: "restricted"})
	request := store.GoExportSetRequest{LifetimeSeconds: 60, MaxArtifactBytes: 1 << 30}
	for n := 0; n < 2; n++ {
		c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/set-preview", Version: fmt.Sprintf("v1.0.%d", n)}
		zip, _ := goPublicationFixture(t, c, fmt.Sprintf("original inert member/%d", n))
		if response := goHTTP(t, s, token, "PUT", "/go/"+repo+"/"+c.Prefix()+".zip", zip); response.Code != 201 {
			t.Fatal("actual publication", response.Code)
		}
		request.Entries = append(request.Entries, store.GoExportSetEntry{Repository: repo, Module: c.Module, Version: c.Version})
	}
	raw, _ := json.Marshal(request)
	response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/preview", raw, "Content-Type", "application/json")
	if response.Code != 403 {
		t.Fatal("unassessed bytes became an eligible selection", response.Code)
	}
	for _, a := range goInventory(t, s, admin, repo) {
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	counts := func() [5]int {
		t.Helper()
		var result [5]int
		if err := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cratectl.events),(SELECT count(*) FROM cratectl.jobs),(SELECT count(*) FROM cratectl.mutations),(SELECT count(*) FROM cratectl.artifact_exports),(SELECT count(*) FROM cratectl.artifact_export_items)`).Scan(&result[0], &result[1], &result[2], &result[3], &result[4])
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := counts()
	response = goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/preview", raw, "Content-Type", "application/json")
	var preview struct {
		Manifest store.GoExportSetManifest `json:"manifest"`
		Object   blob.Object               `json:"object"`
		Physical bool                      `json:"physical_objects_verified"`
		Durable  bool                      `json:"durable_session_created"`
		Trust    string                    `json:"trust"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &preview) != nil || len(preview.Manifest.Entries) != 2 || preview.Physical || preview.Durable || preview.Trust == "" {
		t.Fatal("actual metadata preview", response.Code)
	}
	canonical, err := preview.Manifest.Bytes()
	if err != nil || preview.Object.Digest != crypt.Digest(canonical) || preview.Object.Size != int64(len(canonical)) || preview.Manifest.DependencyClosure || preview.Manifest.CurrentRegistryAdmission || preview.Manifest.ChecksumAuthority {
		t.Fatal("unsigned preview binding/trust changed", err)
	}
	for n, entry := range preview.Manifest.Entries {
		if entry.Version != request.Entries[n].Version || entry.ObservedJournal != preview.Manifest.ObservedJournal || !entry.PreparedAt.Equal(preview.Manifest.PreparedAt) {
			t.Fatal("mixed root observation/order")
		}
	}
	tooSmall := request
	tooSmall.MaxArtifactBytes = preview.Manifest.DeclaredArtifactBytes - 1
	bad, _ := json.Marshal(tooSmall)
	response = goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/preview", bad, "Content-Type", "application/json")
	if response.Code != 413 || bytes.Contains(response.Body.Bytes(), []byte(`"manifest":`)) {
		t.Fatal("byte-budget failure exposed a partial manifest", response.Code)
	}
	wrongEpoch := request
	wrongEpoch.Entries = append([]store.GoExportSetEntry(nil), request.Entries...)
	wrongEpoch.Entries[1].ExpectedSourceRevision = 99
	bad, _ = json.Marshal(wrongEpoch)
	response = goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/preview", bad, "Content-Type", "application/json")
	if response.Code != 409 || bytes.Contains(response.Body.Bytes(), []byte(`"manifest":`)) {
		t.Fatal("late source change exposed a partial manifest", response.Code)
	}
	if after := counts(); after != before {
		t.Fatal("preview changed events/jobs/receipts/exports/items", before, after)
	}
}
