//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestManagementPagesTraverseGrantsAndHiddenGraphs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	token, _ := crypt.Token()
	reader, _ := crypt.Token()
	other, _ := crypt.Token()
	tenant := "pages-" + crypt.Digest([]byte(token))[:12]
	for _, v := range []struct{ tenant, actor, role, token string }{{tenant, "admin", "admin", token}, {tenant, "reader", "reader", reader}, {tenant + "-other", "admin", "admin", other}} {
		if e = store.Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), v.tenant, v.actor, v.role, v.token, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	admin, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	digest := crypt.Digest([]byte("owned graph fixture"))
	child := "app/blobs/sha256:" + digest
	metadata, _ := json.Marshal(map[string]any{"oci_validated": true, "oci_references": []string{child}, "oci_descriptors": map[string]any{child: map[string]any{"digest": "sha256:" + digest, "size": 1, "mediaType": "application/octet-stream"}}})
	// Bulk SQL is fixture setup only, not evidence of publication correctness.
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access,settings) SELECT $1,'a'||lpad(n::text,4,'0'),'generic','hosted','restricted','{"namespace_owners":{"private":"source"}}'::jsonb FROM generate_series(0,1104)n`, tenant)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access) VALUES($1,'z-visible','generic','hosted','restricted'),($1,'graph-pages','oci','hosted','tenant'),($1,'many-files','generic','hosted','tenant')`, tenant)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,'z-visible','reader',true,false)`, tenant)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,decision) SELECT $1,'many-files','file-'||lpad(n::text,4,'0'),$2,1,'application/octet-stream','{}','allowed' FROM generate_series(0,1104)n`, tenant, digest)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,decision) VALUES($1,'many-files','é-package',$2,1,'application/octet-stream','{}','allowed'),($1,'many-files','😀-package',$2,1,'application/octet-stream','{}','allowed'),($1,'many-files','z-package',$2,1,'application/octet-stream','{}','allowed')`, tenant, digest)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,decision) SELECT $1,'graph-pages','app/manifests/sha256:'||lpad(to_hex(n),64,'0'),lpad(to_hex(n),64,'0'),1,'application/vnd.oci.image.manifest.v1+json',$2::jsonb,'allowed' FROM generate_series(0,1104)n`, tenant, metadata)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,decision) VALUES($1,'graph-pages',$2,$3,1,'application/octet-stream','{}','denied'),($1,'graph-pages','zz-readable',$3,1,'application/octet-stream','{}','allowed')`, tenant, child, digest)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	keyfile := filepath.Join(t.TempDir(), "pagination.key")
	key, e := configfile.PaginationKey(keyfile)
	if e != nil {
		t.Fatal(e)
	}
	s := New(db, nil, "https://localhost:38443")
	s.PaginationKey = key
	type row struct {
		Name, Path, Format string
		Settings           map[string]any
		MetadataOmitted    bool `json:"metadata_omitted"`
	}
	type page struct {
		Items          []row
		Next, Previous string
		Limit          int
	}
	get := func(path, credential string) (page, int) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+credential)
		s.ServeHTTP(w, r)
		var p page
		if w.Code == 200 && json.Unmarshal(w.Body.Bytes(), &p) != nil {
			t.Fatal("invalid management response")
		}
		return p, w.Code
	}
	first := func(path, credential string) page {
		p, status := get(path, credential)
		if status != 200 {
			t.Fatalf("list failed: status %d", status)
		}
		return p
	}
	repos := "/api/v1/repositories?limit=37"
	p := first(repos, reader)
	if len(p.Items) != 3 || p.Items[2].Name != "z-visible" || p.Next != "" {
		t.Fatal("grant filtering happened after page limit")
	}
	if settings := p.Items[0].Settings; len(settings) != 1 {
		t.Fatal("reader received source configuration")
	}
	p = first(repos, token)
	names := []string{}
	var last page
	for n := 0; ; n++ {
		if n > 100 {
			t.Fatal("forward cursor did not terminate")
		}
		for _, r := range p.Items {
			names = append(names, r.Name)
		}
		last = p
		if p.Next == "" {
			break
		}
		p = first(repos+"&cursor="+url.QueryEscape(p.Next), token)
	}
	if len(names) != 1108 || !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
		t.Fatal("repository traversal incomplete or duplicated")
	}
	reverse := []string{}
	p = last
	for n := 0; ; n++ {
		if n > 100 {
			t.Fatal("reverse cursor did not terminate")
		}
		block := []string{}
		for _, r := range p.Items {
			block = append(block, r.Name)
		}
		reverse = append(block, reverse...)
		if p.Previous == "" {
			break
		}
		p = first(repos+"&cursor="+url.QueryEscape(p.Previous), token)
	}
	if !slices.Equal(names, reverse) {
		t.Fatal("reverse traversal differs from forward traversal")
	}
	searched := first(repos+"&q=Z-VISIBLE", reader)
	if len(searched.Items) != 1 || searched.Items[0].Name != "z-visible" {
		t.Fatal("search missed a late authorized repository")
	}
	if p = first(repos+"&q=%25", token); len(p.Items) != 0 {
		t.Fatal("search interpreted a literal percent as wildcard")
	}
	files := "/api/v1/repositories/many-files/artifacts?limit=41&metadata=omit"
	p = first(files, reader)
	paths := []string{}
	for n := 0; ; n++ {
		if n > 100 {
			t.Fatal("artifact traversal did not terminate")
		}
		for _, r := range p.Items {
			if !r.MetadataOmitted {
				t.Fatal("summary lost omission flag")
			}
			paths = append(paths, r.Path)
		}
		if p.Next == "" {
			break
		}
		p = first(files+"&cursor="+url.QueryEscape(p.Next), reader)
	}
	if len(paths) != 1108 || !slices.IsSorted(paths) || len(slices.Compact(slices.Clone(paths))) != 1108 {
		t.Fatal("artifact traversal incomplete")
	}
	reversePaths := []string{}
	for n := 0; ; n++ {
		if n > 100 {
			t.Fatal("artifact reverse traversal did not terminate")
		}
		block := []string{}
		for _, r := range p.Items {
			block = append(block, r.Path)
		}
		reversePaths = append(block, reversePaths...)
		if p.Previous == "" {
			break
		}
		p = first(files+"&cursor="+url.QueryEscape(p.Previous), reader)
	}
	if !slices.Equal(paths, reversePaths) {
		t.Fatal("UTF-8 reverse artifact traversal differs from forward")
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type,metadata,decision)SELECT $1,'many-files','budget-'||n::text,$2,1,'application/octet-stream',jsonb_build_object('payload',repeat('x',700)),'allowed' FROM generate_series(0,2)n`, tenant, digest)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	s.ManagementMetadataBytes = 1024
	budgetURL := "/api/v1/repositories/many-files/artifacts?limit=100&q=budget-"
	p = first(budgetURL, token)
	budgetPaths := []string{}
	for n := 0; ; n++ {
		if n > 5 {
			t.Fatal("byte-budget cursor failed to progress")
		}
		for _, r := range p.Items {
			budgetPaths = append(budgetPaths, r.Path)
		}
		if len(p.Items) != 1 {
			t.Fatal("metadata byte budget not applied")
		}
		if p.Next == "" {
			break
		}
		p = first(budgetURL+"&cursor="+url.QueryEscape(p.Next), token)
	}
	if !slices.Equal(budgetPaths, []string{"budget-0", "budget-1", "budget-2"}) {
		t.Fatal("byte-shortened page discarded lookahead")
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=jsonb_build_object('payload',repeat('x',1500))WHERE repository='many-files'AND path='budget-1'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	p = first(budgetURL, token)
	if len(p.Items) != 1 || p.Items[0].Path != "budget-0" || p.Next == "" {
		t.Fatal("oversized lookahead prevented earlier bounded page")
	}
	if _, status := get(budgetURL+"&cursor="+url.QueryEscape(p.Next), token); status != 503 {
		t.Fatal("oversized full metadata record did not fail explicitly")
	}
	if p = first(budgetURL+"&metadata=omit", token); len(p.Items) != 3 {
		t.Fatal("summary traversal lost an oversized metadata record")
	}
	referenceURL := "/api/v1/repositories/many-files/artifacts/reference?path=budget-1"
	if _, status := get(referenceURL, token); status != 503 {
		t.Fatal("full reference ignored configured byte budget")
	}
	s.ManagementMetadataBytes = 2048
	if _, status := get(referenceURL, token); status != 200 {
		t.Fatal("operator could not increase full reference budget")
	}
	s.ManagementMetadataBytes = 8 << 20
	graphs := "/api/v1/repositories/graph-pages/artifacts?limit=100&metadata=omit"
	p = first(graphs, reader)
	if len(p.Items) != 0 || p.Next == "" {
		t.Fatal("hidden graph page did not preserve progress")
	}
	graphCursor := p.Next
	seen := map[string]bool{}
	visible := []string{}
	for n := 0; ; n++ {
		if n > 30 {
			t.Fatal("hidden graph cursor did not terminate")
		}
		for _, r := range p.Items {
			visible = append(visible, r.Path)
		}
		if p.Next == "" {
			break
		}
		if seen[p.Next] {
			t.Fatal("cursor repeated")
		}
		seen[p.Next] = true
		p = first(graphs+"&cursor="+url.QueryEscape(p.Next), reader)
	}
	if !slices.Equal(visible, []string{"zz-readable"}) {
		t.Fatal("graph policy bypass or omitted late visible artifact")
	}
	reverseVisible := []string{}
	for n := 0; ; n++ {
		if n > 30 {
			t.Fatal("hidden reverse page did not terminate")
		}
		for _, r := range p.Items {
			reverseVisible = append(reverseVisible, r.Path)
		}
		if p.Previous == "" {
			break
		}
		p = first(graphs+"&cursor="+url.QueryEscape(p.Previous), reader)
	}
	if !slices.Equal(reverseVisible, []string{"zz-readable"}) {
		t.Fatal("reverse hidden traversal changed visibility")
	}
	// Restart with the same persisted key; cursor is not a process-local session.
	s = New(db, nil, "https://localhost:38443")
	s.PaginationKey, e = configfile.PaginationKey(keyfile)
	if e != nil {
		t.Fatal(e)
	}
	if _, status := get(graphs+"&cursor="+url.QueryEscape(graphCursor), reader); status != 200 {
		t.Fatal("restart invalidated persisted cursor")
	}
	for _, v := range []struct{ path, credential string }{{graphs + "&q=changed&cursor=" + url.QueryEscape(graphCursor), reader}, {graphs + "&cursor=" + url.QueryEscape(graphCursor), token}, {graphs + "&cursor=" + url.QueryEscape(graphCursor), other}, {files + "&cursor=" + url.QueryEscape(graphCursor), reader}} {
		if _, status := get(v.path, v.credential); status != 400 {
			t.Fatalf("differently scoped cursor accepted: %d", status)
		}
	}
	for _, query := range []string{"limit=0", "limit=1001", "limit=1&limit=2", "q=%00", "q=" + strings.Repeat("x", 257), "cursor=p1.invalid", "cursor=" + strings.Repeat("a", 3001), "q=bad%XX", "unknown=true"} {
		if _, status := get("/api/v1/repositories?"+query, token); status != 400 {
			t.Fatalf("invalid query accepted: %q (%d)", query, status)
		}
	}
	pageBefore := first("/api/v1/repositories?q=a&limit=2", token)
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,access)VALUES($1,'a0000-new','generic','hosted','restricted')`, tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	afterInsert := first("/api/v1/repositories?q=a&limit=2&cursor="+url.QueryEscape(pageBefore.Next), token)
	if len(afterInsert.Items) != 2 || afterInsert.Items[0].Name != "a0002" {
		t.Fatal("concurrent earlier insertion shifted or repeated the continuation")
	}
	restart := first("/api/v1/repositories?q=a0000&limit=10", token)
	if len(restart.Items) != 2 || restart.Items[1].Name != "a0000-new" {
		t.Fatal("first-page restart missed earlier insertion")
	}
	if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.repository_grants SET can_read=false WHERE repository='z-visible'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if p = first(repos, reader); len(p.Items) != 2 {
		t.Fatal("revoked grant persisted into new page")
	}
	if e = store.Revoke(ctx, os.Getenv("CRATECTL_OWNER_DSN"), token); e != nil {
		t.Fatal(e)
	}
	if _, status := get("/api/v1/repositories?q=a&limit=1&cursor="+url.QueryEscape(pageBefore.Next), token); status != 401 {
		t.Fatal("revoked credential reused cursor")
	}
	t.Logf("verified 1108 repositories, 1108 artifact references including UTF-8 keys, and 1105 hidden OCI roots; forward/reverse traversal, filters, restart, scope and revocation")
}
