//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func mavenHTTP(t *testing.T, s *Server, token, method, p, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, p, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	for n := 0; n < len(headers); n += 2 {
		r.Header.Set(headers[n], headers[n+1])
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func mavenRepositories(t *testing.T, s *Server, i store.Identity, repos ...store.Repository) {
	t.Helper()
	if e := s.DB.Tx(context.Background(), i, true, func(tx pgx.Tx) error {
		for _, repo := range repos {
			if e := store.CreateRepository(context.Background(), tx, i, repo); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func mavenPut(t *testing.T, s *Server, token, repo, p, body string) {
	t.Helper()
	w := mavenHTTP(t, s, token, "PUT", "/r/"+repo+"/"+p, body)
	if w.Code != 201 {
		t.Fatal("publish", p, w.Code, w.Body.String())
	}
}
func mavenReadModel(t *testing.T, w *httptest.ResponseRecorder) mavenMetadata {
	t.Helper()
	var md mavenMetadata
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &md) != nil {
		t.Fatal("native metadata", w.Code, w.Body.String())
	}
	return md
}
func mavenDeny(t *testing.T, s *Server, i store.Identity, repo, p string) {
	t.Helper()
	a, e := s.DB.Artifact(context.Background(), i, repo, p)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DB.Tx(context.Background(), i, true, func(tx pgx.Tx) error {
		_, e := store.Decide(context.Background(), tx, i, repo, p, a.Digest, "denied")
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestMavenMetadataUnionCurrentPolicyAndNativeHTTP(t *testing.T) {
	s, _, token, i := schemaServer(t)
	mavenRepositories(t, s, i, store.Repository{Name: "first", Format: "maven", Access: "restricted"}, store.Repository{Name: "second", Format: "maven"}, store.Repository{Name: "combined", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}})
	dir := "org/example/tool/"
	p := dir + "maven-metadata.xml"
	for _, v := range []struct{ repo, version string }{{"first", "1.0"}, {"second", "2.0"}} {
		for _, ext := range []string{"pom", "jar"} {
			mavenPut(t, s, token, v.repo, dir+v.version+"/tool-"+v.version+"."+ext, v.version+"-"+ext)
		}
	}
	mavenPut(t, s, token, "first", p, `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>1.0</version><version>99.0</version></versions></versioning></metadata>`)
	mavenPut(t, s, token, "second", p, `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>2.0</version></versions></versioning></metadata>`)
	w := mavenHTTP(t, s, token, "GET", "/r/combined/"+p, "")
	md := mavenReadModel(t, w)
	if strings.Join(md.Versioning.Versions, ",") != "1.0,2.0" {
		t.Fatal("not complete/current", w.Body.String())
	}
	etag, body := w.Header().Get("ETag"), w.Body.String()
	if w = mavenHTTP(t, s, token, "GET", "/r/combined/"+p, "", "If-None-Match", etag); w.Code != 304 {
		t.Fatal("conditional metadata", w.Code)
	}
	if w = mavenHTTP(t, s, token, "HEAD", "/r/combined/"+p, ""); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD metadata", w.Code, w.Body.Len())
	}
	if w = mavenHTTP(t, s, token, "GET", "/r/combined/"+p, "", "Range", "bytes=0-9"); w.Code != 206 || w.Body.String() != body[:10] {
		t.Fatal("range metadata", w.Code, w.Body.String())
	}
	if w = mavenHTTP(t, s, token, "GET", "/r/combined/"+p+".sha256", ""); w.Code != 200 || w.Body.String() != crypt.Digest([]byte(body)) {
		t.Fatal("merged checksum", w.Code, w.Body.String())
	}
	// A stale client replacement must not erase a newer immutable POM/version.
	mavenPut(t, s, token, "first", dir+"3.0/tool-3.0.pom", "3-pom")
	mavenPut(t, s, token, "first", p, `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>1.0</version></versions></versioning></metadata>`)
	md = mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/combined/"+p, ""))
	if strings.Join(md.Versioning.Versions, ",") != "1.0,2.0,3.0" || md.Versioning.Latest != "3.0" {
		t.Fatal("lost concurrent version", md.Versioning)
	}
	mavenPut(t, s, token, "second", dir+"1.0/tool-1.0.pom", "lower-source-1-pom")
	mavenDeny(t, s, i, "first", dir+"1.0/tool-1.0.pom")
	mavenDeny(t, s, i, "second", dir+"2.0/tool-2.0.jar")
	w = mavenHTTP(t, s, token, "GET", "/r/combined/"+p, "", "If-None-Match", etag)
	md = mavenReadModel(t, w)
	if strings.Join(md.Versioning.Versions, ",") != "3.0" || w.Header().Get("ETag") == etag {
		t.Fatal("policy-stale metadata", w.Body.String())
	}
	if w = mavenHTTP(t, s, token, "GET", "/r/combined/"+dir+"1.0/tool-1.0.pom", ""); w.Code != 403 {
		t.Fatal("denied collision fell through", w.Code)
	}
	if w = mavenHTTP(t, s, token, "PUT", "/r/first/"+dir+"3.0/tool-3.0.pom", "different"); w.Code != 409 {
		t.Fatal("release was mutable", w.Code)
	}
}

func TestMavenSnapshotClassifiersLatestBuildAndNoDeniedFallback(t *testing.T) {
	s, _, token, i := schemaServer(t)
	mavenRepositories(t, s, i, store.Repository{Name: "snapshots", Format: "maven"})
	dir := "org/example/tool/1.0-SNAPSHOT/"
	for _, file := range []string{"tool-1.0-20261029.120000-9.pom", "tool-1.0-20261029.120000-9.jar", "tool-1.0-20261029.120000-10.jar", "tool-1.0-20261029.120000-9-sources.jar"} {
		mavenPut(t, s, token, "snapshots", dir+file, file)
	}
	p := dir + "maven-metadata.xml"
	mavenPut(t, s, token, "snapshots", p, `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20261029.120000</timestamp><buildNumber>9</buildNumber></snapshot></versioning></metadata>`)
	md := mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p, ""))
	if md.Versioning.Snapshot.Build != 10 || len(md.Versioning.Snapshots) != 3 {
		t.Fatal(md.Versioning)
	}
	for _, entry := range md.Versioning.Snapshots {
		if entry.Extension == "jar" && entry.Classifier == "" && entry.Value != "1.0-20261029.120000-10" {
			t.Fatal("counter ordering", entry)
		}
	}
	mavenDeny(t, s, i, "snapshots", dir+"tool-1.0-20261029.120000-10.jar")
	md = mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p, ""))
	for _, entry := range md.Versioning.Snapshots {
		if entry.Extension == "jar" && entry.Classifier == "" {
			t.Fatal("older JAR substituted for denied newest", entry)
		}
	}
	for _, invalid := range []string{`<!DOCTYPE metadata SYSTEM "https://example.invalid/x"><metadata/>`, `<metadata><groupId>elsewhere</groupId><artifactId>tool</artifactId></metadata>`} {
		if w := mavenHTTP(t, s, token, "PUT", "/r/snapshots/"+p, invalid); w.Code != 400 {
			t.Fatal("invalid metadata accepted", w.Code)
		}
	}
	s.NativeVersionLimit = 1
	if w := mavenHTTP(t, s, token, "GET", "/r/snapshots/"+p, ""); w.Code != 503 {
		t.Fatal("record budget silently truncated", w.Code)
	}
}

func TestMavenProxyCatalogValidationAndKnownDigestDenial(t *testing.T) {
	s, _, token, i := schemaServer(t)
	s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
	var valid atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		parent := strings.TrimSuffix(p, ".sha256")
		body := ""
		switch parent {
		case "org/example/tool/maven-metadata.xml":
			if valid.Load() {
				body = `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>`
			} else {
				body = `<metadata><groupId>wrong</groupId><artifactId>tool</artifactId></metadata>`
			}
		case "org/example/tool/2.0/tool-2.0.pom":
			body = "two-pom"
		default:
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		if strings.HasSuffix(p, ".sha256") {
			_, _ = w.Write([]byte(crypt.Digest([]byte(body))))
		} else {
			_, _ = w.Write([]byte(body))
		}
	}))
	defer up.Close()
	mavenRepositories(t, s, i, store.Repository{Name: "remote", Format: "maven", Mode: "proxy", Settings: store.RepositorySettings{Upstream: &upstream.Config{URL: up.URL + "/", Networks: []string{"127.0.0.1/32"}}, Cache: store.CacheSettings{FreshSeconds: 60, RequireChecksum: true}}})
	p := "org/example/tool/maven-metadata.xml"
	if w := mavenHTTP(t, s, token, "GET", "/r/remote/"+p, ""); w.Code != 502 {
		t.Fatal("invalid upstream metadata served", w.Code, w.Body.String())
	}
	if _, e := s.DB.MavenCatalogArtifact(context.Background(), i, "remote", p); e == nil {
		t.Fatal("invalid upstream XML acquired a reference")
	}
	valid.Store(true)
	md := mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/remote/"+p, "", "Cache-Control", "no-cache"))
	if len(md.Versioning.Versions) != 2 {
		t.Fatal(md)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/remote/org/example/tool/2.0/tool-2.0.pom", ""); w.Code != 200 {
		t.Fatal("proxy POM", w.Code, w.Body.String())
	}
	mavenDeny(t, s, i, "remote", "org/example/tool/2.0/tool-2.0.pom")
	md = mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/remote/"+p, ""))
	if strings.Join(md.Versioning.Versions, ",") != "1.0" {
		t.Fatal("known denied version advertised", md.Versioning)
	}
	// A cached catalog from a former authority cannot become the catalog of a
	// newly selected authority merely because its freshness has not elapsed.
	if e := s.DB.Tx(context.Background(), i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(context.Background(), `UPDATE cratectl.repositories SET settings=jsonb_set(settings,'{upstream,url}',to_jsonb($1::text)) WHERE name='remote'`, up.URL+"/changed/")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/remote/"+p, ""); w.Code != 503 || !strings.Contains(w.Body.String(), "maven_source_changed") {
		t.Fatal("old authority catalog reused after source change", w.Code, w.Body.String())
	}
}

func TestMavenMetadataGrantTenantReviewAndVersionOwnership(t *testing.T) {
	s, d, token, i := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, i,
		store.Repository{Name: "first", Format: "maven", Access: "restricted"}, store.Repository{Name: "second", Format: "maven"},
		store.Repository{Name: "combined", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}},
		store.Repository{Name: "owned", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}, NamespaceOwners: map[string]string{"org/example/tool/2.0/": "first"}}},
		store.Repository{Name: "reviewed", Format: "maven", Mode: "group", RequireReview: true, Settings: store.RepositorySettings{Members: []string{"second"}}})
	mavenPut(t, s, token, "first", "org/example/tool/1.0/tool-1.0.pom", "first-pom")
	mavenPut(t, s, token, "second", "org/example/tool/2.0/tool-2.0.pom", "second-pom")
	p := "org/example/tool/maven-metadata.xml"
	md := mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/owned/"+p, ""))
	if strings.Join(md.Versioning.Versions, ",") != "1.0" {
		t.Fatal("owned missing version appeared", md)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/owned/org/example/tool/2.0/tool-2.0.pom", ""); w.Code != 404 {
		t.Fatal("namespace ownership fell through", w.Code)
	}
	if w := mavenHTTP(t, s, token, "GET", "/r/reviewed/"+p, ""); w.Code != 404 {
		t.Fatal("unassessed discovery passed stronger group review", w.Code)
	}
	a, e := s.DB.Artifact(ctx, i, "second", "org/example/tool/2.0/tool-2.0.pom")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := store.Decide(ctx, tx, i, "second", a.Path, a.Digest, "allowed")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	_ = mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/reviewed/"+p, ""))
	reader, _ := crypt.Token()
	if e = store.Provision(ctx, d.OwnerDSN, i.Tenant, "maven-reader", "reader", reader, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	grant := func(allowed bool) {
		t.Helper()
		if e = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'first','maven-reader',$2,false)ON CONFLICT(tenant,repository,actor)DO UPDATE SET can_read=excluded.can_read`, i.Tenant, allowed)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	grant(true)
	w := mavenHTTP(t, s, reader, "GET", "/r/combined/"+p, "")
	_ = mavenReadModel(t, w)
	etag := w.Header().Get("ETag")
	grant(false)
	w = mavenHTTP(t, s, reader, "GET", "/r/combined/"+p, "", "If-None-Match", etag)
	if w.Code != 403 || strings.Contains(w.Body.String(), "<version>") {
		t.Fatal("revoked grant served conditional metadata", w.Code, w.Body.String())
	}
	other, _ := crypt.Token()
	if e = store.Provision(ctx, d.OwnerDSN, "maven-other", "operator", "admin", other, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	otherIdentity, e := s.DB.Authenticate(ctx, other)
	if e != nil {
		t.Fatal(e)
	}
	mavenRepositories(t, s, otherIdentity, store.Repository{Name: "first", Format: "maven"}, store.Repository{Name: "combined", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first"}}})
	mavenPut(t, s, other, "first", "org/example/tool/77.0/tool-77.0.pom", "other-pom")
	md = mavenReadModel(t, mavenHTTP(t, s, other, "GET", "/r/combined/"+p, ""))
	if strings.Join(md.Versioning.Versions, ",") != "77.0" {
		t.Fatal("tenant metadata collision", md)
	}
	md = mavenReadModel(t, mavenHTTP(t, s, token, "GET", "/r/combined/"+p, ""))
	if strings.Contains(strings.Join(md.Versioning.Versions, ","), "77.0") {
		t.Fatal("cross-tenant metadata")
	}
}

func TestMavenChecksumPublicationReceiptsAreScopedAndAtomic(t *testing.T) {
	s, d, token, i := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, i, store.Repository{Name: "first", Format: "maven"}, store.Repository{Name: "second", Format: "maven"})
	p := "org/example/tool/maven-metadata.xml"
	one := `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>1.0</version></versions></versioning></metadata>`
	two := strings.Replace(one, "1.0", "2.0", 1)
	mavenPut(t, s, token, "first", p, one)
	mavenPut(t, s, token, "first", p, two)
	mavenPut(t, s, token, "second", p, two)
	old := crypt.Digest([]byte(one))
	if w := mavenHTTP(t, s, token, "PUT", "/r/first/"+p+".sha256", old); w.Code != 201 {
		t.Fatal("delayed accepted checksum", w.Code, w.Body.String())
	}
	if w := mavenHTTP(t, s, token, "PUT", "/r/second/"+p+".sha256", old); w.Code != 400 {
		t.Fatal("receipt crossed repository", w.Code)
	}
	writer, _ := crypt.Token()
	if e := store.Provision(ctx, d.OwnerDSN, i.Tenant, "other-publisher", "writer", writer, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if w := mavenHTTP(t, s, writer, "PUT", "/r/first/"+p+".sha256", old); w.Code != 400 {
		t.Fatal("receipt crossed actor", w.Code)
	}
	if w := mavenHTTP(t, s, token, "PUT", "/r/first/"+p+".sha256", strings.Repeat("0", 64)); w.Code != 400 {
		t.Fatal("unknown checksum accepted", w.Code)
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(ctx)
	if _, e = owner.Exec(ctx, `ALTER TABLE cratectl.mutations ADD CONSTRAINT cratectl_reject_maven_receipt CHECK(key NOT LIKE 'maven-metadata-%') NOT VALID`); e != nil {
		t.Fatal(e)
	}
	before, e := s.DB.MavenCatalogArtifact(ctx, i, "first", p)
	if e != nil {
		t.Fatal(e)
	}
	events, e := s.DB.Events(ctx, i, 0)
	if e != nil {
		t.Fatal(e)
	}
	three := strings.Replace(one, "1.0", "3.0", 1)
	if w := mavenHTTP(t, s, token, "PUT", "/r/first/"+p, three); w.Code != 503 {
		t.Fatal("receipt fault did not fail publication", w.Code)
	}
	after, e := s.DB.MavenCatalogArtifact(ctx, i, "first", p)
	if e != nil || after.Digest != before.Digest {
		t.Fatal("receipt failure committed pointer", e)
	}
	currentEvents, e := s.DB.Events(ctx, i, 0)
	if e != nil || len(currentEvents) != len(events) {
		t.Fatal("receipt failure committed journal", e)
	}
	if e = s.DB.MavenChecksumReceipt(ctx, i, "first", p, "sha256", crypt.Digest([]byte(three))); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("failed publication acquired receipt", e)
	}
}
