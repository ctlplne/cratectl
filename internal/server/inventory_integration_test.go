//go:build integration && (darwin || linux)

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
)

func TestInventoryAdmissionReplaySurvivesUnsupportedStorageRoot(t *testing.T) {
	s, ctx, i, _ := uploadFixture(t)
	root := t.TempDir()
	objects, e := blob.New(root, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	s.Blobs = objects
	invoke := func(body, key string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/maintenance/storage-inventories", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Idempotency-Key", key)
		s.management(w, r, i)
		return w
	}
	first := invoke(`{}`, "owned-root-replay")
	if first.Code != 202 {
		t.Fatalf("admission: %d %s", first.Code, first.Body.String())
	}
	if e = os.Symlink(t.TempDir(), filepath.Join(root, i.Tenant)); e != nil {
		t.Fatal(e)
	}
	replay := invoke(`{}`, "owned-root-replay")
	if replay.Code != 202 || replay.Header().Get("Idempotent-Replayed") != "true" || replay.Body.String() != first.Body.String() {
		t.Fatalf("storage failure changed recorded response: %d %s", replay.Code, replay.Body.String())
	}
	if changed := invoke(`{"page_size":1}`, "owned-root-replay"); changed.Code != 409 {
		t.Fatalf("conflicting replay: %d %s", changed.Code, changed.Body.String())
	}
	if fresh := invoke(`{}`, "owned-fresh-admit"); fresh.Code != 503 {
		t.Fatalf("unsupported root admitted: %d %s", fresh.Code, fresh.Body.String())
	}
}
