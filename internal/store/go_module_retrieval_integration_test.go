//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/testdb"
	"ctlplne.dev/cratectl/internal/upstream"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"github.com/jackc/pgx/v5"
)

type goIntakeFixture struct {
	s       *Store
	d       testdb.Database
	i       Identity
	lease   Retrieval
	result  RetrievalResult
	objects *blob.Local
}

func newGoIntakeFixture(t *testing.T) goIntakeFixture {
	t.Helper()
	d, s, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := s.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	settings, _ := json.Marshal(RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/go/source/", Networks: []string{"127.0.0.1/32"}}})
	// Deliberate lab-only row: public Go proxy creation remains rejected. This
	// exercises the internal transaction before enabling its network/API path.
	if e = s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings)VALUES($1,'owned','go','proxy',true,'restricted',$2)`, i.Tenant, settings)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	objects, e := blob.New(t.TempDir(), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	f := goIntakeFixture{s: s, d: d, i: i, objects: objects}
	f.result = f.bundle(t, "original bytes")
	f.lease, e = s.AcquireRetrieval(ctx, i, "owned", f.result.GoModule.Objects[0].Path, "owned-intake-lease", false)
	if e != nil || !f.lease.Acquired {
		t.Fatal("acquire complete-bundle root", e)
	}
	return f
}

func (f goIntakeFixture) bundle(t *testing.T, payload string) RetrievalResult {
	t.Helper()
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/intake", Version: "v1.0.0"}
	mod := []byte("module " + c.Module + "\n\ngo 1.26.0\n")
	info := []byte(`{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	var body bytes.Buffer
	z := zip.NewWriter(&body)
	for _, file := range []struct {
		name string
		body []byte
	}{{"go.mod", mod}, {"assets/owned.txt", []byte(payload)}} {
		w, e := z.Create(c.Module + "@" + c.Version + "/" + file.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(file.body); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := gomodule.InspectRepresentations(context.Background(), bytes.NewReader(body.Bytes()), int64(body.Len()), c, mod, info, ziparchive.Limits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64}); e != nil {
		t.Fatal("validate independent inert representations before staging", e)
	}
	as := []Artifact{}
	metadata := GoModuleMetadata{Profile: GoModuleProfile, Module: c.Module, Version: c.Version, Digests: map[string]string{}}
	var root blob.Object
	for _, file := range []struct {
		kind string
		body []byte
	}{{"zip", body.Bytes()}, {"mod", mod}, {"info", info}} {
		object, e := f.objects.Put(context.Background(), f.i.Tenant, bytes.NewReader(file.body), "", int64(len(file.body)))
		if e != nil {
			t.Fatal(e)
		}
		if file.kind == "zip" {
			root = object
		}
		metadata.Digests[file.kind] = object.Digest
		as = append(as, Artifact{Path: c.Prefix() + "." + file.kind, Digest: object.Digest, Size: object.Size, MediaType: goMedia[file.kind]})
	}
	raw, _ := json.Marshal(metadata)
	for n := range as {
		as[n].Metadata = raw
	}
	return RetrievalResult{Status: 200, Object: &root, Metadata: raw, MediaType: goMedia["zip"], FreshSeconds: 60, StaleSeconds: 60, GoModule: &GoModulePublication{Objects: as}}
}

func (f goIntakeFixture) counts(t *testing.T) (references, integrity, ready int) {
	t.Helper()
	if e := f.s.Tx(context.Background(), f.i, false, func(tx pgx.Tx) error {
		for _, query := range []struct {
			sql string
			n   *int
		}{{`SELECT count(*) FROM cratectl.artifacts WHERE repository='owned'`, &references}, {`SELECT count(*) FROM cratectl.jobs WHERE queue='integrity'`, &integrity}, {`SELECT count(*) FROM cratectl.events WHERE payload::jsonb->>'kind'='proxy.retrieval.ready'`, &ready}} {
			if e := tx.QueryRow(context.Background(), query.sql).Scan(query.n); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return
}

func TestGoModuleRetrievalAtomicBundleCacheAndCurrentPolicy(t *testing.T) {
	f := newGoIntakeFixture(t)
	ctx := context.Background()
	if e := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); e != nil {
		t.Fatal(e)
	}
	if a, b, c := f.counts(t); a != 3 || b != 3 || c != 1 {
		t.Fatal("bundle references, integrity intents and ready event did not commit together", a, b, c)
	}
	for _, a := range f.result.GoModule.Objects {
		if _, e := f.s.Artifact(ctx, f.i, "owned", a.Path); !errors.Is(e, ErrDenied) {
			t.Fatal("unassessed intake became readable", e)
		}
		cache, e := f.s.Retrieval(ctx, f.i, "owned", a.Path)
		if e != nil || cache.State != "ready" || cache.ValidationRoot != f.lease.Path || cache.ValidationGeneration != f.lease.Generation || !cache.Fresh() {
			t.Fatal("sibling validation receipt not bound to the root lease", cache.State, e)
		}
	}
	if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='owned'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	retained := map[string]Artifact{}
	for _, want := range f.result.GoModule.Objects {
		got, e := f.s.Artifact(ctx, f.i, "owned", want.Path)
		if e != nil || got.Digest != want.Digest || got.Size != want.Size {
			t.Fatal("approved exact bundle reference", e)
		}
		// PostgreSQL's jsonb representation need not preserve JSON whitespace
		// or key order. Compare the exact persisted snapshot before/after the
		// rejected intake, while immutable object bytes retain their own hashes.
		retained[want.Path] = got
	}
	if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned' AND path=$1`, f.lease.Path)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.Artifact(ctx, f.i, "owned", f.result.GoModule.Objects[1].Path); !errors.Is(e, ErrDenied) {
		t.Fatal("current ZIP denial did not govern the cached mod sibling", e)
	}
	if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='owned'`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("completed lease replayed publication", e)
	}
	lease, e := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "changed-intake", true)
	if e != nil || !lease.Acquired {
		t.Fatal(e)
	}
	if e = f.s.CompleteRetrieval(ctx, f.i, lease, f.bundle(t, "changed forbidden bytes")); !errors.Is(e, ErrConflict) {
		t.Fatal("proxy overwrote an immutable module version", e)
	}
	if a, b, c := f.counts(t); a != 3 || b != 3 || c != 1 {
		t.Fatal("replay/conflict changed references or emitted new publication intents", a, b, c)
	}
	for p, want := range retained {
		got, e := f.s.Artifact(ctx, f.i, "owned", p)
		if e != nil || got.Digest != want.Digest || got.Size != want.Size || got.MediaType != want.MediaType || got.SourceRevision != want.SourceRevision || !got.Created.Equal(want.Created) || !bytes.Equal(got.Metadata, want.Metadata) {
			t.Fatal("immutable conflict changed a retained representation", e)
		}
	}
}

func TestGoModuleRetrievalFullOutboxRollsBackEveryReference(t *testing.T) {
	f := newGoIntakeFixture(t)
	ctx := context.Background()
	policy := QueuePolicy{Queue: "integrity", Capacity: 1, MaxRunning: 1, MaxAttempts: 2, RetrySeconds: 1, RetryMaxSeconds: 2}
	if _, e := f.s.SetQueuePolicy(ctx, f.i, "small-go-intake", "small-go-intake", policy); e != nil {
		t.Fatal(e)
	}
	if e := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); !errors.Is(e, ErrQueueFull) {
		t.Fatal("full integrity outbox admitted bundle", e)
	}
	if a, b, c := f.counts(t); a != 0 || b != 0 || c != 0 {
		t.Fatal("failed outbox committed partial bundle or ready event", a, b, c)
	}
	if e := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		var siblings int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.retrievals WHERE repository='owned' AND path<>$1`, f.lease.Path).Scan(&siblings); e != nil {
			return e
		}
		if siblings != 0 {
			t.Error("failed bundle retained sibling validation receipts", siblings)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	lease, e := f.s.Retrieval(ctx, f.i, "owned", f.lease.Path)
	if e != nil || lease.State == "fetching" {
		t.Fatal("queue failure stranded the owned lease", lease.State, e)
	}
}

func TestGoModuleRetrievalFencesLeaseSourceGrantAndTenant(t *testing.T) {
	for _, scenario := range []string{"lease", "source", "grant", "tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGoIntakeFixture(t)
			ctx := context.Background()
			i := f.i
			want := ErrLeaseLost
			switch scenario {
			case "lease", "source":
				if e := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
					if scenario == "source" {
						_, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET source_revision=source_revision+1 WHERE name='owned'`)
						return e
					}
					_, e := tx.Exec(ctx, `UPDATE cratectl.retrievals SET lease_until='epoch' WHERE repository='owned'`)
					return e
				}); e != nil {
					t.Fatal(e)
				}
				if scenario == "source" {
					want = ErrSourceChanged
				} else if replacement, e := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "replacement", false); e != nil || !replacement.Acquired || replacement.Generation <= f.lease.Generation {
					t.Fatal("expired lease did not acquire a newer fence", e)
				}
			case "grant", "tenant":
				token, e := crypt.Token()
				if e != nil {
					t.Fatal(e)
				}
				tenant := f.i.Tenant
				if scenario == "tenant" {
					tenant = "other-intake-team"
				}
				if e = Provision(ctx, f.d.OwnerDSN, tenant, "intake-reader", "reader", token, time.Now().Add(time.Hour)); e != nil {
					t.Fatal(e)
				}
				i, e = f.s.Authenticate(ctx, token)
				if e != nil {
					t.Fatal(e)
				}
				if scenario == "grant" {
					if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write)VALUES($1,'owned','intake-reader',true,false)`, f.i.Tenant)
						return e
					}); e != nil {
						t.Fatal(e)
					}
					if _, e = f.s.Repository(ctx, i, "owned"); e != nil {
						t.Fatal("reader lacked authority before revocation", e)
					}
					if e = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
						_, e := tx.Exec(ctx, `UPDATE cratectl.repository_grants SET can_read=false WHERE repository='owned' AND actor='intake-reader'`)
						return e
					}); e != nil {
						t.Fatal(e)
					}
				}
				want = ErrDenied
				if scenario == "tenant" {
					want = ErrNotFound
				}
			}
			if e := f.s.CompleteRetrieval(ctx, i, f.lease, f.result); !errors.Is(e, want) {
				t.Fatal("stale or unauthorized intake crossed its fence", scenario, e)
			}
			if a, b, c := f.counts(t); a != 0 || b != 0 || c != 0 {
				t.Fatal("rejected intake left a partial publication", a, b, c)
			}
		})
	}
}
