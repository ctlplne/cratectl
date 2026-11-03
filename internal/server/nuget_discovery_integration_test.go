//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestNuGetDiscoveryUsesCurrentCatalogPolicyAndGrants(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	s.PublicURL = "https://registry.example"
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "nuget", Access: "restricted", RequireReview: true})
	paths := map[string]string{}
	digests := map[string]string{}
	publish := func(id, v, key string) {
		t.Helper()
		data, _ := nugetNupkgFixture(t, id, v)
		body, ct := nugetMultipart(t, data, 0)
		if w := nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, ct); w.Code != 201 {
			t.Fatal("publish", w.Code, w.Body.String())
		}
		version, e := nuget.VersionKey(v)
		if e != nil {
			t.Fatal(e)
		}
		paths[key] = store.NuGetPath(strings.ToLower(id), version)
		digests[key] = crypt.Digest(data)
	}
	for _, v := range []string{"1.0.0", "2.0.0", "10.0.0", "11.0.0-rc", "12.0.0+Owned"} {
		publish("Owned.Package", v, v)
	}
	publish("Other.Package", "1.0.0", "other")
	registration := "/nuget/owned/registration/owned.package/index.json"
	read := func(token, p string) *httptest.ResponseRecorder { return nugetHTTP(t, s, token, "GET", p, nil, "") }
	search := func(query, version string, total int64) {
		t.Helper()
		w := read(token, "/nuget/owned/query"+query)
		var result struct {
			Total int64 `json:"totalHits"`
			Data  []struct {
				Version  string
				Versions []struct{ Version string }
			}
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != total || version != "" && (len(result.Data) != 1 || result.Data[0].Version != version) {
			t.Fatal("search", query, w.Code, w.Body.String())
		}
		if version == "" && len(result.Data) != 0 {
			t.Fatal("unexpected page", w.Body.String())
		}
	}
	search("?q=Owned.Package", "", 0)
	if w := read(token, registration); w.Code != 404 {
		t.Fatal("unreviewed registration visible", w.Code)
	}
	decide := func(v, decision string) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := store.Decide(ctx, tx, admin, "owned", paths[v], digests[v], decision)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	for v := range paths {
		decide(v, "allowed")
	}
	search("?q=owned.package", "10.0.0", 1)
	search("?q=owned.package&prerelease=true", "11.0.0-rc", 1)
	search("?q=owned.package&semVerLevel=2.0.0", "12.0.0+Owned", 1)
	search("?q=%25", "", 0)
	search("?q=owned.package&skip=1&take=1", "", 1)
	search("?take=1", "1.0.0", 2)
	search("?skip=1&take=1", "10.0.0", 2)
	search("?skip=2&take=1", "", 2)
	w := read(token, registration)
	z, e := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if e != nil || w.Code != 200 {
		t.Fatal("registration", w.Code, e)
	}
	raw, e := io.ReadAll(z)
	z.Close()
	var index struct {
		Count int
		Items []struct {
			Count        int
			Lower, Upper string
			Items        []struct {
				Catalog map[string]any `json:"catalogEntry"`
			}
		}
	}
	if e != nil || json.Unmarshal(raw, &index) != nil || index.Count != 1 || index.Items[0].Count != 5 || index.Items[0].Lower != "1.0.0" || index.Items[0].Upper != "12.0.0" {
		t.Fatal("numeric registration ordering", string(raw), e)
	}
	if e = s.DB.SetNuGetListing(ctx, admin, "owned", "Owned.Package", "10.0.0", false); e != nil {
		t.Fatal(e)
	}
	search("?q=owned.package", "2.0.0", 1)
	leaf := read(token, "/nuget/owned/registration/owned.package/10.0.0.json")
	z, e = gzip.NewReader(bytes.NewReader(leaf.Body.Bytes()))
	if e != nil || leaf.Code != 200 {
		t.Fatal(leaf.Code, e)
	}
	raw, e = io.ReadAll(z)
	z.Close()
	var record struct {
		Listed  bool
		Catalog string `json:"catalogEntry"`
	}
	if e != nil || json.Unmarshal(raw, &record) != nil || record.Listed || !strings.HasSuffix(record.Catalog, "/10.0.0/catalog.json") {
		t.Fatal("unlisted metadata lost", string(raw), e)
	}
	if w := read(token, "/nuget/owned/registration/owned.package/10.0.0/catalog.json"); w.Code != 200 {
		t.Fatal("catalog URL missing", w.Code)
	}
	decide("12.0.0+Owned", "denied")
	search("?q=owned.package&semVerLevel=2.0.0&prerelease=true", "11.0.0-rc", 1)
	if w := read(token, "/nuget/owned/registration/owned.package/12.0.0/catalog.json"); w.Code != 403 {
		t.Fatal("denied catalog visible", w.Code)
	}
	old := s.NativeMetadataBytes
	s.NativeMetadataBytes = 1
	for _, p := range []string{registration, "/nuget/owned/query"} {
		if w := read(token, p); w.Code != 503 {
			t.Fatal("metadata budget", p, w.Code)
		}
	}
	s.NativeMetadataBytes = old
	reader, _ := crypt.Token()
	if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, "discovery-reader", "reader", reader, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{registration, "/nuget/owned/query"} {
		if w := read(reader, p); w.Code != 403 {
			t.Fatal("grant bypass", p, w.Code)
		}
	}
	if e = s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,'owned','discovery-reader',true,false)`, admin.Tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{registration, "/nuget/owned/query"} {
		if w := read(reader, p); w.Code != 200 {
			t.Fatal("granted read", p, w.Code)
		}
	}
	if e = store.Revoke(ctx, d.OwnerDSN, reader); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{registration, "/nuget/owned/query"} {
		if w := read(reader, p); w.Code != 401 {
			t.Fatal("revoked read", p, w.Code)
		}
	}
	// An earlier package missing its projection fails discovery explicitly.
	if e = s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{catalog,profile}','"nuspec-catalog-v1"'::jsonb,true) WHERE repository='owned' AND path=$1`, paths["1.0.0"])
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if w := read(token, "/nuget/owned/query"); w.Code != 503 || !strings.Contains(w.Body.String(), "nuget_catalog_rebuild_required") {
		t.Fatal("obsolete projection silently reused", w.Code, w.Body.String())
	}
	if e = s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=metadata-'catalog' WHERE repository='owned' AND path=$1`, paths["1.0.0"])
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if w := read(token, "/nuget/owned/query?q=unmatched"); w.Code != 503 || !strings.Contains(w.Body.String(), "nuget_catalog_rebuild_required") {
		t.Fatal("legacy package silently omitted", w.Code, w.Body.String())
	}
	input := store.NuGetReindexRequest{After: paths["other"], Limit: 1, DryRun: true, Reason: "Owned old package rebuild regression"}
	preview, e := s.DB.RebuildNuGetCatalog(ctx, admin, "owned", "", "", input, 8<<20)
	var result store.NuGetReindexResult
	if e != nil || json.Unmarshal(preview.Body, &result) != nil || result.Changed != 1 || result.Examined != 1 || !result.More || result.After != paths["1.0.0"] {
		t.Fatal("rebuild preview", string(preview.Body), e)
	}
	if w := read(token, "/nuget/owned/query"); w.Code != 503 {
		t.Fatal("preview wrote projection", w.Code)
	}
	input.DryRun = false
	first, e := s.DB.RebuildNuGetCatalog(ctx, admin, "owned", "reindex-owned-first", "owned-rebuild", input, 8<<20)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.DB.RebuildNuGetCatalog(ctx, admin, "owned", "reindex-owned-first", "owned-rebuild", input, 8<<20)
	if e != nil || !bytes.Equal(first.Body, again.Body) {
		t.Fatal("rebuild receipt did not replay", e)
	}
	search("?q=owned.package", "2.0.0", 1)
	request := lifecycleHTTP(t, s, token)
	if w := request("PUT", "/api/v1/repositories/owned/artifacts/lifecycle", store.ArtifactStateRequest{Path: paths["2.0.0"], Digest: digests["2.0.0"], Action: "delete", Reason: "Owned discovery retirement"}, "discovery-retire"); w.Code != 200 {
		t.Fatal("retire discovery fixture", w.Code, w.Body.String())
	}
	search("?q=owned.package", "1.0.0", 1)
	if w := read(token, "/nuget/owned/registration/owned.package/2.0.0.json"); w.Code != 404 {
		t.Fatal("retired registration leaf visible", w.Code)
	}
	if e := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		var n int
		e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='nuget.catalog.rebuilt'`).Scan(&n)
		if e == nil && n != 1 {
			t.Fatal("replay duplicated event", n)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestNuGetRebuildRollsBackMetadataWhenOutboxIsFull(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "nuget"})
	data, _ := nugetNupkgFixture(t, "Owned.Package", "1.0.0")
	body, ct := nugetMultipart(t, data, 0)
	if w := nugetHTTP(t, s, token, "PUT", "/nuget/owned/api/v2/package", body, ct); w.Code != 201 {
		t.Fatal(w.Code)
	}
	if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=metadata-'catalog' WHERE repository='owned'`); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	_, e := s.DB.RebuildNuGetCatalog(ctx, admin, "owned", "full-queue-rebuild", "owned", store.NuGetReindexRequest{Limit: 10, Reason: "Owned rollback regression"}, 8<<20)
	if !errors.Is(e, store.ErrQueueFull) {
		t.Fatal("full queue accepted rebuild", e)
	}
	if e := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		var present bool
		e := tx.QueryRow(ctx, `SELECT metadata ? 'catalog' FROM cratectl.artifacts WHERE repository='owned'`).Scan(&present)
		if e == nil && present {
			t.Fatal("rolled back batch changed catalog")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
