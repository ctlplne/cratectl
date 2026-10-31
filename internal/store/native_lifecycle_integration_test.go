//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

func nativeLifecycleFixture(t *testing.T, format string) (*Store, context.Context, Identity, Artifact) {
	t.Helper()
	_, db, _, token, _ := schemaFixture(t)
	ctx := context.Background()
	i, e := db.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, Repository{Name: "native", Format: format}) }); e != nil {
		t.Fatal(e)
	}
	a := Artifact{Path: "owned/package.bin", Digest: crypt.Digest([]byte("Owned native lifecycle bytes")), Size: 28, MediaType: "application/octet-stream"}
	switch format {
	case "maven":
		a.Path = "org/example/owned/1.0/owned-1.0.jar"
		a.MediaType = "application/java-archive"
	case "npm":
		a.Path = NPMPath("@owned/package", "1.0.0")
		a.Metadata, _ = json.Marshal(map[string]any{"name": "@owned/package", "version": "1.0.0", "package": map[string]any{"name": "@owned/package", "version": "1.0.0"}})
	case "pypi":
		a.Path = "owned_package-1.0-py3-none-any.whl"
		a.Metadata, _ = json.Marshal(PythonFile{Name: "owned-package", Version: "1.0", Filename: a.Path, Validated: true})
	}
	if format == "npm" {
		e = db.PublishNPM(ctx, i, "native", "@owned/package", []Artifact{a}, map[string]string{"latest": "1.0.0"})
	} else if format == "pypi" {
		e = db.PublishPython(ctx, i, "native", a)
	} else {
		e = db.Publish(ctx, i, "native", []Artifact{a})
	}
	if e != nil {
		t.Fatal(e)
	}
	return db, ctx, i, a
}

func TestMaterializedNativeProxyRefreshRechecksHoldAndRetirementAtPublication(t *testing.T) {
	for _, format := range []string{"generic", "maven"} {
		t.Run(format, func(t *testing.T) {
			_, db, _, token, _ := schemaFixture(t)
			ctx := context.Background()
			admin, e := db.Authenticate(ctx, token)
			if e != nil {
				t.Fatal(e)
			}
			repo := Repository{Name: "native-proxy", Format: format, Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/r/source/", Networks: []string{"127.0.0.1/32"}}}}
			if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, admin, repo) }); e != nil {
				t.Fatal(e)
			}
			objects, e := blob.New(t.TempDir(), 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			result := func(value string) RetrievalResult {
				t.Helper()
				object, e := objects.Put(ctx, admin.Tenant, bytes.NewBufferString(value), "", int64(len(value)))
				if e != nil {
					t.Fatal(e)
				}
				return RetrievalResult{Status: 200, Object: &object, FreshSeconds: 60}
			}
			path := "org/example/owned/1.0/owned-1.0.jar"
			acquire := func() Retrieval {
				t.Helper()
				key, _ := crypt.Token()
				lease, e := db.AcquireRetrieval(ctx, admin, repo.Name, path, key, true)
				if e != nil || !lease.Acquired {
					t.Fatal(lease, e)
				}
				return lease
			}
			first, second := result("first durable bytes"), result("replacement durable bytes")
			if e = db.CompleteRetrieval(ctx, admin, acquire(), first); e != nil {
				t.Fatal(e)
			}
			a, e := db.Artifact(ctx, admin, repo.Name, path)
			if e != nil {
				t.Fatal(e)
			}
			// Begin retrieval before placing protection: admission alone is not authority.
			inflight := acquire()
			if _, e = db.ChangeArtifactState(ctx, admin, repo.Name, "hold-proxy-native", "hold-proxy-native", lifecycleInput(a, "hold", 0), 100, nil); e != nil {
				t.Fatal(e)
			}
			if e = db.CompleteRetrieval(ctx, admin, inflight, second); !errors.Is(e, ErrHeld) {
				t.Fatal("in-flight replacement crossed a newly placed hold", e)
			}
			if current, e := db.Artifact(ctx, admin, repo.Name, path); e != nil || current.Digest != a.Digest {
				t.Fatal("held bytes changed", current, e)
			}
			rejected, e := db.Retrieval(ctx, admin, repo.Name, path)
			if e != nil || rejected.State != "ready" || rejected.LastError != "reference_held" || !rejected.FreshUntil.Equal(inflight.FreshUntil) || rejected.ETag != inflight.ETag {
				t.Fatal("rejected replacement stranded lease or invented freshness", rejected, e)
			}
			// A same-byte refresh does not change the preservation subject or revision.
			if e = db.CompleteRetrieval(ctx, admin, acquire(), first); e != nil {
				t.Fatal("same-byte refresh rejected while held", e)
			}
			if _, e = db.ChangeArtifactState(ctx, admin, repo.Name, "release-proxy-native", "release-proxy-native", lifecycleInput(a, "release_hold", 1), 100, nil); e != nil {
				t.Fatal(e)
			}
			before, _, e := db.HoldHistory(ctx, admin, repo.Name, path, ListRequest{Limit: 100})
			if e != nil || len(before) != 2 {
				t.Fatal(before, e)
			}
			pending := acquire()
			if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `INSERT INTO cratectl.queue_policies(tenant,queue,capacity) VALUES($1,'events',1) ON CONFLICT(tenant,queue) DO UPDATE SET capacity=1`, admin.Tenant)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if e = db.CompleteRetrieval(ctx, admin, pending, second); !errors.Is(e, ErrQueueFull) {
				t.Fatal("replacement bypassed event queue admission", e)
			}
			if state, e := db.ArtifactState(ctx, admin, repo.Name, path); e != nil || state.Revision != 2 || state.Digest != a.Digest {
				t.Fatal("queue failure partially rebound lifecycle", state, e)
			}
			if current, e := db.Artifact(ctx, admin, repo.Name, path); e != nil || current.Digest != a.Digest {
				t.Fatal("queue failure partially replaced bytes", current, e)
			}
			if e = db.Tx(ctx, admin, true, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE cratectl.queue_policies SET capacity=100000 WHERE queue='events'`)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if e = db.CompleteRetrieval(ctx, admin, acquire(), second); e != nil {
				t.Fatal("released reference could not refresh", e)
			}
			state, e := db.ArtifactState(ctx, admin, repo.Name, path)
			if e != nil || state.Revision != 3 || state.Digest != second.Object.Digest || state.Held {
				t.Fatal("replacement did not advance exact identity", state, e)
			}
			after, _, e := db.HoldHistory(ctx, admin, repo.Name, path, ListRequest{Limit: 100})
			oldJSON, _ := json.Marshal(before)
			newJSON, _ := json.Marshal(after)
			if e != nil || !bytes.Equal(oldJSON, newJSON) {
				t.Fatal("replacement rewrote preservation receipts", before, after, e)
			}
			listed, _, _, e := db.HoldPage(ctx, admin, HoldListRequest{ListRequest: ListRequest{Limit: 100}, State: "all"})
			if e != nil || len(listed) != 0 {
				t.Fatal("old receipt falsely attached to replacement digest", listed, e)
			}
			if e = db.Tx(ctx, admin, false, func(tx pgx.Tx) error {
				var snapshot []byte
				if e := tx.QueryRow(ctx, `SELECT payload::jsonb#>'{data,reference_replacement}' FROM cratectl.events WHERE sequence=$1`, state.ChangeSequence).Scan(&snapshot); e != nil {
					return e
				}
				var replacement referenceReplacement
				if e := json.Unmarshal(snapshot, &replacement); e != nil {
					return e
				}
				if replacement.Previous.Digest != a.Digest || replacement.Previous.Revision != 2 || replacement.Current.Digest != state.Digest || replacement.Current.ChangeSequence != state.ChangeSequence {
					t.Fatal("publication event lacks exact previous/new lifecycle", replacement)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if _, e = db.ChangeArtifactState(ctx, admin, repo.Name, "stale-native-delete", "stale-native-delete", lifecycleInput(a, "delete", 2), 100, nil); !errors.Is(e, ErrLifecycleRevision) {
				t.Fatal("old preview acted on replacement bytes", e)
			}
			a.Digest = state.Digest
			inflight = acquire()
			if _, e = db.ChangeArtifactState(ctx, admin, repo.Name, "delete-refreshed-native", "delete-refreshed-native", lifecycleInput(a, "delete", 3), 100, nil); e != nil {
				t.Fatal(e)
			}
			if e = db.CompleteRetrieval(ctx, admin, inflight, first); !errors.Is(e, ErrLeaseLost) {
				t.Fatal("retirement failed to fence an in-flight refresh", e)
			}
			if _, e = db.AcquireRetrieval(ctx, admin, repo.Name, path, "deleted-refresh", true); !errors.Is(e, ErrDeleted) {
				t.Fatal("new refresh admitted after retirement", e)
			}
		})
	}
}

func TestMaterializedNativeLifecycleProtectsRetiresAndRestoresExactReference(t *testing.T) {
	for _, format := range []string{"generic", "maven", "npm", "pypi"} {
		t.Run(format, func(t *testing.T) {
			db, ctx, admin, a := nativeLifecycleFixture(t, format)
			if _, e := db.ChangeArtifactState(ctx, admin, "native", "place-native-hold", "place-native-hold", lifecycleInput(a, "hold", 0), 100, nil); e != nil {
				t.Fatal("native materialized reference cannot be preserved", e)
			}
			if _, e := db.ChangeArtifactState(ctx, admin, "native", "delete-held-native", "delete-held-native", lifecycleInput(a, "delete", 1), 100, nil); !errors.Is(e, ErrHeld) {
				t.Fatal("delete bypassed current preservation", e)
			}
			if _, e := db.Artifact(ctx, admin, "native", a.Path); e != nil {
				t.Fatal("hold incorrectly blocked authorized serving", e)
			}
			if _, e := db.ChangeArtifactState(ctx, admin, "native", "release-native-hold", "release-native-hold", lifecycleInput(a, "release_hold", 1), 100, nil); e != nil {
				t.Fatal(e)
			}
			if _, e := db.ChangeArtifactState(ctx, admin, "native", "delete-native-reference", "delete-native-reference", lifecycleInput(a, "delete", 2), 100, nil); e != nil {
				t.Fatal(e)
			}
			if _, e := db.Artifact(ctx, admin, "native", a.Path); !errors.Is(e, ErrDeleted) {
				t.Fatal("retired reference remains servable", e)
			}
			if e := db.Publish(ctx, admin, "native", []Artifact{a}); !errors.Is(e, ErrDeleted) {
				t.Fatal("same-byte publication resurrected a tombstone", e)
			}
			if format == "npm" {
				versions, tags, e := db.NPMState(ctx, admin, "native", "@owned/package", 100, 1<<20)
				if e != nil || len(versions) != 0 || len(tags) != 0 {
					t.Fatal("native npm metadata advertised a retired version", versions, tags, e)
				}
			}
			if format == "pypi" {
				view, e := db.PythonView(ctx, admin, "native", "owned-package", 100, 1<<20)
				if e != nil || len(view) != 1 || len(view[0].Files) != 1 || !view[0].Files[0].Blocked {
					t.Fatal("native Python metadata failed to retain blocked retirement identity", view, e)
				}
			}
			proof, e := db.RestorationGraph(ctx, admin, "native", lifecycleInput(a, "restore", 3))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.ChangeArtifactState(ctx, admin, "native", "restore-native-reference", "restore-native-reference", lifecycleInput(a, "restore", 3), 100, proof); e != nil {
				t.Fatal(e)
			}
			if restored, e := db.Artifact(ctx, admin, "native", a.Path); e != nil || restored.Digest != a.Digest {
				t.Fatal(restored, e)
			}
			// Mutable discovery is not a package lifecycle subject.
			catalog := a
			switch format {
			case "maven":
				catalog.Path = "org/example/owned/maven-metadata.xml"
			case "npm":
				catalog.Path, catalog.MediaType = NPMCatalogPath("@owned/package"), NPMCatalogMedia
			case "pypi":
				catalog.Path, catalog.MediaType = PythonCatalogPath("owned-package"), PythonCatalogMedia
			default:
				return
			}
			if e = db.Publish(ctx, admin, "native", []Artifact{catalog}); e != nil {
				t.Fatal(e)
			}
			if _, e = db.ChangeArtifactState(ctx, admin, "native", "reject-catalog-hold", "reject-catalog-hold", lifecycleInput(catalog, "hold", 0), 100, nil); !errors.Is(e, ErrConflict) {
				t.Fatal("mutable discovery accepted as a preservation subject", e)
			}
		})
	}
}

func TestMaterializedNativeProxyMetadataRetainsDeletedSourceIdentity(t *testing.T) {
	for _, format := range []string{"npm", "pypi"} {
		t.Run(format, func(t *testing.T) {
			_, db, _, token, _ := schemaFixture(t)
			ctx := context.Background()
			i, e := db.Authenticate(ctx, token)
			if e != nil {
				t.Fatal(e)
			}
			repo := Repository{Name: "native-proxy", Format: format, Mode: "proxy", Settings: RepositorySettings{Upstream: &upstream.Config{URL: "http://127.0.0.1:38443/r/source/", Networks: []string{"127.0.0.1/32"}}}}
			if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error { return CreateRepository(ctx, tx, i, repo) }); e != nil {
				t.Fatal(e)
			}
			objects, e := blob.New(t.TempDir(), 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			put := func(p string, metadata []byte, media string, catalog *NativeCatalogPublication) Artifact {
				t.Helper()
				object, e := objects.Put(ctx, i.Tenant, bytes.NewReader(metadata), "", int64(len(metadata)))
				if e != nil {
					t.Fatal(e)
				}
				lease, e := db.AcquireRetrieval(ctx, i, repo.Name, p, p, true)
				if e != nil {
					t.Fatal(e)
				}
				if e = db.CompleteRetrieval(ctx, i, lease, RetrievalResult{Status: 200, Object: &object, Metadata: metadata, MediaType: media, NativeCatalog: catalog, FreshSeconds: 60}); e != nil {
					t.Fatal(e)
				}
				return Artifact{Path: p, Digest: object.Digest, Size: object.Size}
			}
			name, version, filename := "owned", "1.0.0", "owned-1.0-py3-none-any.whl"
			key := crypt.Digest([]byte("retained source descriptor"))
			path, catalogPath, media := NPMBlobPath(name, key), NPMCatalogPath(name), NPMCatalogMedia
			coordinate := version
			metadata, _ := json.Marshal(map[string]any{"name": name, "version": version, "package": map[string]string{"name": name, "version": version}})
			if format == "pypi" {
				path, catalogPath, media = PythonBlobPath(name, key, filename), PythonCatalogPath(name), PythonCatalogMedia
				coordinate, version = filename, "1.0"
				metadata, _ = json.Marshal(PythonFile{Name: name, Version: version, Filename: filename, Validated: true})
			}
			publication := &NativeCatalogPublication{Name: name, Entries: map[string]string{coordinate: key}, Sources: []NativeSource{{Key: key, Format: format, Name: name, Coordinate: coordinate, Version: version, URL: "http://127.0.0.1:38443/source/package", Metadata: metadata}}}
			var encoded []byte
			if format == "npm" {
				encoded, _ = json.Marshal(NPMCatalog{Name: name, Versions: publication.Entries, Tags: map[string]string{"latest": version}})
			} else {
				encoded, _ = json.Marshal(PythonCatalog{Name: name, Files: publication.Entries})
			}
			put(catalogPath, encoded, media, publication)
			a := put(path, metadata, "application/octet-stream", nil)
			if _, e = db.ChangeArtifactState(ctx, i, repo.Name, "retire-proxy-package", "retire-proxy-package", lifecycleInput(a, "delete", 0), 100, nil); e != nil {
				t.Fatal(e)
			}
			if format == "npm" {
				view, e := db.NPMView(ctx, i, repo.Name, name, 10, 10, 1<<20)
				if e != nil || len(view) != 1 || len(view[0].Versions) != 1 || !view[0].Versions[0].Blocked || view[0].Versions[0].Key != key {
					t.Fatal("npm proxy lost retired first-source identity", view, e)
				}
			} else {
				view, e := db.PythonView(ctx, i, repo.Name, name, 10, 1<<20)
				if e != nil || len(view) != 1 || len(view[0].Files) != 1 || !view[0].Files[0].Blocked || view[0].Files[0].Key != key {
					t.Fatal("Python proxy lost retired first-source identity", view, e)
				}
			}
			if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
				if e := CreateRepository(ctx, tx, i, Repository{Name: "fallback", Format: format}); e != nil {
					return e
				}
				return CreateRepository(ctx, tx, i, Repository{Name: "native-group", Format: format, Mode: "group", Settings: RepositorySettings{Members: []string{repo.Name, "fallback"}}})
			}); e != nil {
				t.Fatal(e)
			}
			fallback := a
			fallback.Metadata = metadata
			fallback.MediaType = "application/octet-stream"
			if format == "npm" {
				fallback.Path = NPMPath(name, version)
				e = db.PublishNPM(ctx, i, "fallback", name, []Artifact{fallback}, map[string]string{"latest": version})
			} else {
				fallback.Path = filename
				e = db.PublishPython(ctx, i, "fallback", fallback)
			}
			if e != nil {
				t.Fatal(e)
			}
			group, e := db.Repository(ctx, i, "native-group")
			if e != nil {
				t.Fatal(e)
			}
			member, e := db.Repository(ctx, i, "fallback")
			if e != nil {
				t.Fatal(e)
			}
			snapshot := SourceSnapshot{Repository: member.Name, Revision: member.SourceRevision, Groups: map[string]int64{group.Name: group.SourceRevision}}
			if _, e = db.ArtifactSelection(ctx, i, member.Name, fallback.Path, snapshot); !errors.Is(e, ErrDeleted) {
				t.Fatal("pinned fallback bypassed a currently selected proxy tombstone", e)
			}
			// A new descriptor at the same native coordinate has its own retained
			// reference. The old descriptor's tombstone cannot become a version ban.
			newKey := crypt.Digest([]byte("replacement source descriptor"))
			publication.Entries = map[string]string{coordinate: newKey}
			publication.Sources[0].Key = newKey
			publication.Sources[0].URL += "/replacement"
			if format == "npm" {
				encoded, _ = json.Marshal(NPMCatalog{Name: name, Versions: publication.Entries, Tags: map[string]string{"latest": version}})
			} else {
				encoded, _ = json.Marshal(PythonCatalog{Name: name, Files: publication.Entries})
			}
			put(catalogPath, encoded, media, publication)
			if _, e = db.ArtifactSelection(ctx, i, member.Name, fallback.Path, snapshot); e != nil {
				t.Fatal("old descriptor tombstone became a package-wide denial", e)
			}
			publication.Entries = map[string]string{}
			publication.Sources = nil
			if format == "npm" {
				encoded, _ = json.Marshal(NPMCatalog{Name: name, Versions: publication.Entries, Tags: map[string]string{}})
			} else {
				encoded, _ = json.Marshal(PythonCatalog{Name: name, Files: publication.Entries})
			}
			put(catalogPath, encoded, media, publication)
			if selected, e := db.ArtifactSelection(ctx, i, member.Name, fallback.Path, snapshot); e != nil || selected.Digest != fallback.Digest {
				t.Fatal("historical proxy tombstone blocked ordinary fallback after catalog removal", selected, e)
			}
			if _, e = db.Artifact(ctx, i, repo.Name, path); !errors.Is(e, ErrDeleted) {
				t.Fatal("catalog removal resurrected the retained old reference", e)
			}
		})
	}
}
