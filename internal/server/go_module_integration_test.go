//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

const goFixtureInstant = "2026-01-02T03:04:05Z"

func goHTTP(t testing.TB, s *Server, token, method, p string, data []byte, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, p, bytes.NewReader(data))
	r.SetBasicAuth("token", token)
	if method == "PUT" {
		r.Header.Set("X-Cratectl-Module-Time", goFixtureInstant)
	}
	for n := 0; n < len(headers); n += 2 {
		r.Header.Set(headers[n], headers[n+1])
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func goInventory(t *testing.T, s *Server, i store.Identity, repo string) []store.Artifact {
	t.Helper()
	as, e := s.DB.Artifacts(context.Background(), i, repo, "", true)
	if e != nil {
		t.Fatal(e)
	}
	return as
}
func TestGoModuleAtomicPublicationReviewDiscoveryAndImmutableReplay(t *testing.T) {
	s, database, token, admin := schemaServer(t)
	ctx := context.Background()
	baselineEvents, e := s.DB.Events(ctx, admin, 0)
	if e != nil {
		t.Fatal(e)
	}
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "go", Access: "restricted", RequireReview: true})
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0"}
	data, mod := goPublicationFixture(t, c, "first exact owned bytes")
	endpoint := "/go/owned/" + c.Prefix()
	latest := "/go/owned/go.cratectl.invalid/!owned/app/@latest"
	if w := goHTTP(t, s, token, "GET", latest, nil); w.Code != 404 {
		t.Fatal("empty module lost normal not-found semantics", w.Code)
	}
	published := goHTTP(t, s, token, "PUT", endpoint+".zip", data)
	if published.Code != 201 {
		t.Fatal(published.Code, published.Body.String())
	}
	replay := goHTTP(t, s, token, "PUT", endpoint+".zip", data)
	if replay.Code != 201 || !bytes.Equal(replay.Body.Bytes(), published.Body.Bytes()) {
		t.Fatal("identical response replay", replay.Code)
	}
	as := goInventory(t, s, admin, "owned")
	if len(as) != 3 {
		t.Fatal("partial publication", len(as))
	}
	info, e := gomodule.VersionInfo(c, goFixtureInstant)
	if e != nil {
		t.Fatal(e)
	}
	expected := map[string][]byte{"zip": data, "mod": mod, "info": info}
	approve := func(a store.Artifact, decision string) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := store.Decide(ctx, tx, admin, "owned", a.Path, a.Digest, decision)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	for _, a := range as {
		if !strings.HasSuffix(a.Path, ".zip") {
			approve(a, "allowed")
		}
	}
	for kind := range expected {
		if w := goHTTP(t, s, token, "GET", endpoint+"."+kind, nil); w.Code != 403 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatal("partial review exposed representation", kind, w.Code)
		}
	}
	list := "/go/owned/go.cratectl.invalid/!owned/app/@v/list"
	if w := goHTTP(t, s, token, "GET", list, nil); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("unreviewed version discovered", w.Code, w.Body.String())
	}
	if w := goHTTP(t, s, token, "GET", latest, nil); w.Code != 403 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("unreviewed latest permitted native source fallback", w.Code)
	}
	for _, a := range as {
		approve(a, "allowed")
	}
	for kind, want := range expected {
		w := goHTTP(t, s, token, "GET", endpoint+"."+kind, nil)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) || w.Header().Get("ETag") != `"sha256:`+crypt.Digest(want)+`"` {
			t.Fatal("exact representation", kind, w.Code)
		}
		if head := goHTTP(t, s, token, "HEAD", endpoint+"."+kind, nil); head.Code != 200 || head.Body.Len() != 0 {
			t.Fatal("HEAD", kind, head.Code)
		}
		if notModified := goHTTP(t, s, token, "GET", endpoint+"."+kind, nil, "If-None-Match", w.Header().Get("ETag")); notModified.Code != 304 {
			t.Fatal("conditional", kind, notModified.Code)
		}
	}
	if w := goHTTP(t, s, token, "GET", endpoint+".zip", nil, "Range", "bytes=1-8"); w.Code != 206 || !bytes.Equal(w.Body.Bytes(), data[1:9]) {
		t.Fatal("range", w.Code)
	}
	if w := goHTTP(t, s, token, "GET", list, nil); w.Code != 200 || w.Body.String() != "v1.0.0\n" {
		t.Fatal("complete list", w.Code, w.Body.String())
	}
	if w := goHTTP(t, s, token, "GET", latest, nil); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), info) {
		t.Fatal("latest", w.Code)
	}
	changed, _ := goPublicationFixture(t, c, "different immutable bytes")
	if w := goHTTP(t, s, token, "PUT", endpoint+".zip", changed); w.Code != 409 {
		t.Fatal("changed ZIP accepted", w.Code)
	}
	if w := goHTTP(t, s, token, "PUT", endpoint+".zip", data, "X-Cratectl-Module-Time", "2026-01-03T03:04:05Z"); w.Code != 409 {
		t.Fatal("changed info accepted", w.Code)
	}
	events, e := s.DB.Events(ctx, admin, 0)
	if e != nil || len(events) != len(baselineEvents)+1 {
		t.Fatal("replay/conflict added an event", len(events), e)
	}
	restarted := New(s.DB, s.Blobs, s.PublicURL)
	if w := goHTTP(t, restarted, token, "GET", endpoint+".zip", nil); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("handler recreation", w.Code)
	}
	for _, a := range as {
		if strings.HasSuffix(a.Path, ".zip") {
			approve(a, "denied")
		}
	}
	if w := goHTTP(t, s, token, "GET", latest, nil); w.Code != 403 {
		t.Fatal("denied latest permitted native source fallback", w.Code)
	}
	for kind := range expected {
		if w := goHTTP(t, restarted, token, "GET", endpoint+"."+kind, nil); w.Code != 403 {
			t.Fatal("denied sibling exposed", kind, w.Code)
		}
	}
	if w := goHTTP(t, restarted, token, "GET", latest, nil); w.Code != 403 || strings.Contains(w.Body.String(), c.Version) {
		t.Fatal("denied latest exposed a version or became fallback-eligible", w.Code)
	}
	// Simulate damage inside this disposable test database, after restoring policy.
	// Incomplete versions must stop Go's comma-separated proxy fallback.
	for _, a := range as {
		approve(a, "allowed")
	}

	// This deliberate corruption uses only the owner of this fresh fixture DB.
	// Runtime retains SELECT/INSERT/UPDATE and receives no DELETE/BYPASSRLS grant.
	owner, e := pgx.Connect(ctx, database.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	_, e = owner.Exec(ctx, `DELETE FROM cratectl.artifacts WHERE tenant=$1 AND repository='owned' AND path=$2`, admin.Tenant, c.Prefix()+".info")
	owner.Close(ctx)
	if e != nil {
		t.Fatal(e)
	}

	for _, p := range []string{endpoint + ".zip", endpoint + ".info", list, latest} {
		if w := goHTTP(t, restarted, token, "GET", p, nil); w.Code != 409 {
			t.Fatal("partial version permitted fallback", p, w.Code)
		}
	}

}
func TestGoModuleOutboxRollbackAndConcurrentImmutablePublication(t *testing.T) {
	s, _, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "go"})
	baselineEvents, e := s.DB.Events(ctx, admin, 0)
	if e != nil {
		t.Fatal(e)
	}
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/app", Version: "v1.0.0"}
	first, _ := goPublicationFixture(t, c, "first")
	second, _ := goPublicationFixture(t, c, "second")
	statuses := make(chan int, 2)
	var group sync.WaitGroup
	for _, data := range [][]byte{first, second} {
		group.Add(1)
		go func(data []byte) {
			defer group.Done()
			statuses <- goHTTP(t, s, token, "PUT", "/go/owned/"+c.Prefix()+".zip", data).Code
		}(data)
	}
	group.Wait()
	close(statuses)
	seen := map[int]int{}
	for code := range statuses {
		seen[code]++
	}
	if seen[201] != 1 || seen[409] != 1 {
		t.Fatal("immutable race", seen)
	}
	as := goInventory(t, s, admin, "owned")
	if len(as) != 3 {
		t.Fatal("mixed/partial concurrent publication", len(as))
	}
	for _, a := range as {
		if _, e := store.ValidateGoModuleArtifact(a); e != nil {
			t.Fatal(e)
		}
		if w := goHTTP(t, s, token, "GET", "/go/owned/"+a.Path, nil); w.Code != 200 {
			t.Fatal("inconsistent winning bundle", w.Code)
		}
	}
	if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=1 WHERE queue='events'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	c.Version = "v1.1.0"
	blocked, _ := goPublicationFixture(t, c, "must stay unreferenced")
	if w := goHTTP(t, s, token, "PUT", "/go/owned/"+c.Prefix()+".zip", blocked, "Idempotency-Key", "blocked-go-version"); w.Code != 503 {
		t.Fatal("full outbox ignored", w.Code, w.Body.String())
	}
	if len(goInventory(t, s, admin, "owned")) != 3 {
		t.Fatal("partial outbox rollback")
	}
	events, e := s.DB.Events(ctx, admin, 0)
	if e != nil || len(events) != len(baselineEvents)+1 {
		t.Fatal("event committed on failed publication", len(events), e)
	}
	if e = s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error {
		var count int
		e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.mutations WHERE key='blocked-go-version'`).Scan(&count)
		if e == nil && count != 0 {
			t.Fatal("receipt survived rollback")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
func TestGoModuleCurrentGrantsRevocationAndTenantCollision(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	ctx := context.Background()
	mavenRepositories(t, s, admin, store.Repository{Name: "owned", Format: "go", Access: "restricted"})
	credentials := map[string]string{}
	for _, actor := range []string{"publisher", "consumer", "other"} {
		value, e := crypt.Token()
		if e != nil {
			t.Fatal(e)
		}
		credentials[actor] = value
		tenant, role := admin.Tenant, "reader"
		if actor == "publisher" {
			role = "writer"
		}
		if actor == "other" {
			tenant, role = "go-other", "admin"
		}
		if e = store.Provision(ctx, d.OwnerDSN, tenant, actor, role, value, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	grant := func(actor string, read, write bool) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'owned',$2,$3,$4) ON CONFLICT(tenant,repository,actor) DO UPDATE SET can_read=$3,can_write=$4`, admin.Tenant, actor, read, write)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/app", Version: "v1.0.0"}
	data, _ := goPublicationFixture(t, c, "tenant A")
	endpoint := "/go/owned/" + c.Prefix() + ".zip"
	if w := goHTTP(t, s, credentials["publisher"], "PUT", endpoint, data); w.Code != 403 {
		t.Fatal("ungranted publisher", w.Code)
	}
	grant("publisher", true, true)
	published := goHTTP(t, s, credentials["publisher"], "PUT", endpoint, data)
	if published.Code != 201 {
		t.Fatal("granted publisher", published.Code)
	}
	if w := goHTTP(t, s, credentials["consumer"], "GET", endpoint, nil); w.Code != 403 {
		t.Fatal("ungranted consumer", w.Code)
	}
	grant("consumer", true, false)
	if w := goHTTP(t, s, credentials["consumer"], "GET", endpoint, nil); w.Code != 200 {
		t.Fatal("granted consumer", w.Code)
	}
	if w := goHTTP(t, s, credentials["consumer"], "PUT", endpoint, data); w.Code != 403 {
		t.Fatal("reader published", w.Code)
	}
	publisher, e := s.DB.Authenticate(ctx, credentials["publisher"])
	if e != nil {
		t.Fatal(e)
	}
	as := goInventory(t, s, admin, "owned")
	grant("publisher", true, false)
	if _, e = s.DB.PublishGoModule(ctx, publisher, "owned", as, ""); !errors.Is(e, store.ErrDenied) {
		t.Fatal("durable replay bypassed current write grant", e)
	}
	other, e := s.DB.Authenticate(ctx, credentials["other"])
	if e != nil {
		t.Fatal(e)
	}
	mavenRepositories(t, s, other, store.Repository{Name: "owned", Format: "go"})
	different, _ := goPublicationFixture(t, c, "tenant B")
	if w := goHTTP(t, s, credentials["other"], "PUT", endpoint, different); w.Code != 201 {
		t.Fatal("tenant collision publication", w.Code)
	}
	for who, want := range map[string][]byte{token: data, credentials["other"]: different} {
		w := goHTTP(t, s, who, "GET", endpoint, nil)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) {
			t.Fatal("tenant byte isolation", w.Code)
		}
	}
	if e = store.Revoke(ctx, d.OwnerDSN, credentials["consumer"]); e != nil {
		t.Fatal(e)
	}
	if w := goHTTP(t, s, credentials["consumer"], "GET", endpoint, nil); w.Code != 401 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("revoked consumer", w.Code)
	}
	if w := goHTTP(t, s, credentials["other"], "GET", endpoint, nil); w.Code != 200 {
		t.Fatal("other tenant affected", w.Code)
	}
}

func TestGoModuleGroupsPreservePrecedenceReviewOwnersAndSourceGrants(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	ctx := context.Background()
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0"}
	escapedPrefix := strings.Split(c.Prefix(), "/@v/")[0] + "/"
	mavenRepositories(t, s, admin,
		store.Repository{Name: "first", Format: "go", Access: "restricted"},
		store.Repository{Name: "second", Format: "go", Access: "restricted"},
		store.Repository{Name: "combined", Format: "go", Access: "restricted", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}},
		store.Repository{Name: "reviewed", Format: "go", Access: "restricted", Mode: "group", RequireReview: true, Settings: store.RepositorySettings{Members: []string{"first", "second"}}},
		store.Repository{Name: "pinned", Format: "go", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}, NamespaceOwners: map[string]string{escapedPrefix: "first"}}})
	first, _ := goPublicationFixture(t, c, "first source bytes")
	lower, _ := goPublicationFixture(t, c, "lower priority different bytes")
	for repo, data := range map[string][]byte{"first": first, "second": lower} {
		if w := goHTTP(t, s, token, "PUT", "/go/"+repo+"/"+c.Prefix()+".zip", data); w.Code != 201 {
			t.Fatal(repo, w.Code, w.Body.String())
		}
	}
	next := c
	next.Version = "v1.1.0"
	newer, _ := goPublicationFixture(t, next, "lower source new version")
	if w := goHTTP(t, s, token, "PUT", "/go/second/"+next.Prefix()+".zip", newer); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	get := func(repo string, c gomodule.Coordinate, kind string) *httptest.ResponseRecorder {
		return goHTTP(t, s, token, "GET", "/go/"+repo+"/"+c.Prefix()+"."+kind, nil)
	}
	listPath := strings.Split(c.Prefix(), "/@v/")[0] + "/@v/list"
	if w := get("combined", c, "zip"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), first) || w.Header().Get("X-Cratectl-Repository") != "first" {
		t.Fatal("first source precedence", w.Code)
	}
	if w := get("combined", next, "zip"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), newer) || w.Header().Get("X-Cratectl-Repository") != "second" {
		t.Fatal("new lower source version", w.Code)
	}
	if w := goHTTP(t, s, token, "GET", "/go/combined/"+listPath, nil); w.Code != 200 || w.Body.String() != "v1.0.0\nv1.1.0\n" {
		t.Fatal("complete group list", w.Code, w.Body.String())
	}
	if w := get("reviewed", c, "info"); w.Code != 403 {
		t.Fatal("group weakened review", w.Code)
	}
	decide := func(repo string, a store.Artifact, value string) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error { _, e := store.Decide(ctx, tx, admin, repo, a.Path, a.Digest, value); return e }); e != nil {
			t.Fatal(e)
		}
	}
	firstRefs := goInventory(t, s, admin, "first")
	for _, a := range firstRefs {
		if !strings.HasSuffix(a.Path, ".zip") {
			decide("first", a, "allowed")
		}
	}
	if w := get("reviewed", c, "info"); w.Code != 403 {
		t.Fatal("approved metadata bypassed unreviewed ZIP", w.Code)
	}
	for _, a := range firstRefs {
		decide("first", a, "allowed")
	}
	if w := get("reviewed", c, "zip"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), first) {
		t.Fatal("reviewed exact first source", w.Code)
	}
	if w := goHTTP(t, s, token, "GET", "/go/reviewed/"+listPath, nil); w.Code != 200 || w.Body.String() != "v1.0.0\n" {
		t.Fatal("unreviewed lower discovery", w.Code, w.Body.String())
	}
	if w := get("pinned", next, "zip"); w.Code != 404 {
		t.Fatal("namespace owner fell through", w.Code)
	}
	if w := goHTTP(t, s, token, "GET", "/go/pinned/"+listPath, nil); w.Code != 200 || w.Body.String() != "v1.0.0\n" {
		t.Fatal("namespace-owner discovery mismatch", w.Code, w.Body.String())
	}
	reader, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Provision(ctx, d.OwnerDSN, admin.Tenant, "group-reader", "reader", reader, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	grant := func(repo string, read bool) {
		t.Helper()
		if e := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,$2,'group-reader',$3,false)ON CONFLICT(tenant,repository,actor) DO UPDATE SET can_read=$3`, admin.Tenant, repo, read)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	grant("combined", true)
	grant("second", true)
	endpoint := "/go/combined/" + c.Prefix() + ".zip"
	if w := goHTTP(t, s, reader, "GET", endpoint, nil); w.Code != 403 {
		t.Fatal("missing first grant fell through", w.Code)
	}
	grant("first", true)
	if w := goHTTP(t, s, reader, "GET", endpoint, nil); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), first) {
		t.Fatal("granted group read", w.Code)
	}
	grant("second", false)
	if w := goHTTP(t, s, reader, "GET", "/go/combined/"+listPath, nil); w.Code != 403 {
		t.Fatal("discovery omitted an ungranted consulted source", w.Code)
	}
	for _, a := range firstRefs {
		if strings.HasSuffix(a.Path, ".zip") {
			decide("first", a, "denied")
		}
	}
	if w := get("combined", c, "zip"); w.Code != 403 {
		t.Fatal("denied first source fell through", w.Code)
	}
	if w := goHTTP(t, s, token, "GET", "/go/combined/"+listPath, nil); w.Code != 200 || w.Body.String() != "v1.1.0\n" {
		t.Fatal("blocked first coordinate reappeared from lower source", w.Code, w.Body.String())
	}
	if w := goHTTP(t, s, token, "PUT", endpoint, first); w.Code != 405 {
		t.Fatal("group became publishable", w.Code)
	}
	originalBytes := s.NativeMetadataBytes
	for _, budget := range []struct {
		name     string
		versions int
		bytes    int64
	}{{"rows", 1, originalBytes}, {"metadata bytes", 10000, 1}} {
		s.NativeVersionLimit, s.NativeMetadataBytes = budget.versions, budget.bytes
		for _, operation := range []string{listPath, strings.Replace(listPath, "/@v/list", "/@latest", 1)} {
			for _, method := range []string{"GET", "HEAD"} {
				w := goHTTP(t, s, token, method, "/go/combined/"+operation, nil)
				if w.Code != 503 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !strings.HasPrefix(w.Body.String(), "metadata_budget_exceeded:") || strings.Contains(w.Body.String(), "v1.1.0") {
					t.Fatal("group did not refuse a complete over-budget index", budget.name, operation, method, w.Code, w.Body.String())
				}
			}
		}
	}
	s.NativeVersionLimit, s.NativeMetadataBytes = 10000, originalBytes
	for _, a := range firstRefs {
		decide("first", a, "allowed")
	}
	owner, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	_, e = owner.Exec(ctx, `DELETE FROM cratectl.artifacts WHERE tenant=$1 AND repository='first' AND path=$2`, admin.Tenant, c.Prefix()+".info")
	owner.Close(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if w := get("combined", c, "zip"); w.Code != 409 {
		t.Fatal("partial first source fell through", w.Code)
	}
	if w := goHTTP(t, s, token, "GET", "/go/combined/"+listPath, nil); w.Code != 409 {
		t.Fatal("partial group discovery emitted data", w.Code)
	}
}
