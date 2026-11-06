//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func approveGoChecksumBundle(t *testing.T, f goIntakeFixture) {
	t.Helper()
	ctx := context.Background()
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='owned' AND path NOT LIKE 'go-checksum/%'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func verifyStoredGoChecksum(t *testing.T, f goIntakeFixture, view GoModuleChecksumReadback) *GoChecksumAdmission {
	t.Helper()
	ctx := context.Background()
	object := view.Object()
	file, err := f.objects.OpenVerified(ctx, f.i.Tenant, object.Digest, object.Size)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, object.Size+1))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	marker, err := VerifyGoModuleChecksumReadback(ctx, view, raw)
	if err != nil || marker == nil {
		t.Fatal("original physical proof must authenticate against admitted history", err)
	}
	return marker
}

func TestGoModuleChecksumReadbackRequiresCurrentPolicyProofReceiptAndAuthority(t *testing.T) {
	for _, scenario := range []string{"valid-unassessed-proof", "unapproved-package", "proof-denied", "proof-retired", "proof-media", "proof-metadata", "proof-digest", "proof-size", "missing-current-receipt", "current-key", "source-epoch", "expired", "reader-denied"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			if scenario != "unapproved-package" {
				approveGoChecksumBundle(t, f)
			}
			identity := f.i
			want := error(ErrGoModuleUnvalidated)
			sql := ""
			switch scenario {
			case "valid-unassessed-proof":
				want = nil
			case "unapproved-package":
				want = ErrDenied
			case "proof-denied":
				sql = `UPDATE cratectl.artifacts SET decision='denied' WHERE path LIKE 'go-checksum/%'`
				want = ErrDenied
			case "proof-retired":
				sql = `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,deleted,revision,reason,actor,change_sequence) SELECT tenant,repository,path,digest,true,1,'owned proof retirement','operator',1 FROM cratectl.artifacts WHERE path LIKE 'go-checksum/%'`
				want = ErrDeleted
			case "proof-media":
				sql = `UPDATE cratectl.artifacts SET media_type='application/octet-stream' WHERE path LIKE 'go-checksum/%'`
			case "proof-metadata":
				sql = `UPDATE cratectl.artifacts SET metadata='{}' WHERE path LIKE 'go-checksum/%'`
			case "proof-digest":
				sql = `UPDATE cratectl.artifacts SET digest=repeat('0',64) WHERE path LIKE 'go-checksum/%'`
			case "proof-size":
				sql = `UPDATE cratectl.artifacts SET size=size+1 WHERE path LIKE 'go-checksum/%'`
			case "missing-current-receipt":
				sql = `UPDATE cratectl.retrievals SET generation=generation+1,validation_generation=validation_generation+1 WHERE repository='owned'`
			case "current-key":
				other, _, _ := checksumPublicFixture(t)
				setGoChecksumAuthority(t, f, &other, false)
			case "source-epoch":
				a := log.authority()
				setGoChecksumAuthority(t, f, &a, true)
				want = ErrSourceChanged
			case "expired":
				sql = `UPDATE cratectl.retrievals SET fresh_until='epoch' WHERE repository='owned'`
				want = ErrGoModuleCacheExpired
			case "reader-denied":
				token, err := crypt.Token()
				if err != nil {
					t.Fatal(err)
				}
				if err = Provision(ctx, f.d.OwnerDSN, f.i.Tenant, "proof-reader", "reader", token, time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				identity, err = f.s.Authenticate(ctx, token)
				if err != nil {
					t.Fatal(err)
				}
				want = ErrDenied
			}
			if sql != "" {
				if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql); return err }); err != nil {
					t.Fatal(err)
				}
			}
			view, err := f.s.GoModuleChecksumReadback(ctx, identity, "owned", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, f.lease.SourceRevision)
			if want != nil {
				if !errors.Is(err, want) || !reflect.DeepEqual(view, GoModuleChecksumReadback{}) {
					t.Fatal("current proof policy returned partial inspection trust", scenario, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			marker := verifyStoredGoChecksum(t, f, view)
			for _, a := range f.result.GoModule.Objects {
				got, err := f.s.GoModuleProxyArtifact(ctx, f.i, "owned", a.Path, f.lease.SourceRevision, marker.NativeAdmission())
				if err != nil || got.Digest != a.Digest || got.Size != a.Size {
					t.Fatal("opaque physical-proof admission lost exact representation", err)
				}
			}
			if a, b, c := f.counts(t); a != 4 || b != 4 || c != 1 {
				t.Fatal("readback added approval, publication or work", a, b, c)
			}
			if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, f.lease.SourceRevision); !errors.Is(err, ErrGoModuleUnvalidated) {
				t.Fatal("checksum bytes admitted without request proof", err)
			}
		})
	}
}

func TestGoModuleChecksumPostReadbackGuardRejectsChangedProofPolicyAndBindings(t *testing.T) {
	for _, scenario := range []string{"unchanged", "proof-denied", "proof-retired", "package-denied", "source-epoch", "proof-metadata", "wrong-proof-token", "zip-size", "sibling-size", "wrong-root", "wrong-generation", "wrong-stale-context", "missing-token"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			approveGoChecksumBundle(t, f)
			view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, f.lease.SourceRevision)
			if err != nil {
				t.Fatal(err)
			}
			marker := verifyStoredGoChecksum(t, f, view)
			admission := marker.NativeAdmission()
			want := error(ErrGoModuleUnvalidated)
			sql := ""
			switch scenario {
			case "unchanged":
				want = nil
			case "proof-denied":
				sql = `UPDATE cratectl.artifacts SET decision='denied' WHERE path LIKE 'go-checksum/%'`
				want = ErrDenied
			case "proof-retired":
				sql = `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,deleted,revision,reason,actor,change_sequence) SELECT tenant,repository,path,digest,true,1,'owned proof retirement','operator',1 FROM cratectl.artifacts WHERE path LIKE 'go-checksum/%'`
				want = ErrDeleted
			case "package-denied":
				sql = `UPDATE cratectl.artifacts SET decision='denied' WHERE right(path,5)='.info'`
				want = ErrDenied
			case "source-epoch":
				a := log.authority()
				setGoChecksumAuthority(t, f, &a, true)
				want = ErrSourceChanged
			case "proof-metadata":
				sql = `UPDATE cratectl.artifacts SET metadata='{}' WHERE path LIKE 'go-checksum/%'`
			case "wrong-proof-token":
				copy := *marker
				copy.binding.proofDigest = strings.Repeat("0", 64)
				admission.GoChecksum = &copy
			case "zip-size":
				sql = `UPDATE cratectl.artifacts SET size=size+1 WHERE right(path,4)='.zip'`
			case "sibling-size":
				sql = `UPDATE cratectl.artifacts SET size=size+1 WHERE right(path,5)='.info'`
			case "wrong-root":
				admission.Path += ".other"
			case "wrong-generation":
				admission.Generation++
			case "wrong-stale-context":
				admission.Stale = !admission.Stale
			case "missing-token":
				admission.GoChecksum = nil
			}
			if sql != "" {
				if err = f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql); return err }); err != nil {
					t.Fatal(err)
				}
			}
			a, err := f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, f.lease.SourceRevision, admission)
			if want == nil {
				if err != nil || a.Digest != f.result.Object.Digest {
					t.Fatal("unchanged current proof admission failed", err)
				}
			} else if !errors.Is(err, want) || !reflect.DeepEqual(a, Artifact{}) {
				t.Fatal("post-readback change admitted bytes or partial artifact", err)
			}
		})
	}
}

func TestGoModuleChecksumReadbackRetainsHistoryAcrossGrowthAndSourceEpoch(t *testing.T) {
	for _, scenario := range []string{"consistent-head-growth", "reused-proof-new-source"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			c := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			approveGoChecksumBundle(t, f)
			oldView, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", c, 0)
			if err != nil {
				t.Fatal(err)
			}
			oldMarker := verifyStoredGoChecksum(t, f, oldView)
			revision := int64(0)
			if scenario == "consistent-head-growth" {
				next := f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, "assets/inert.txt", log.Payload)
				attachGoChecksum(t, f, &next, log.publication(t, "v1.1.0", log.Second, 2))
				lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", next.GoModule.Objects[0].Path, "readback-consistent-growth", false)
				if err != nil || !lease.Acquired {
					t.Fatal(err)
				}
				if err = f.s.CompleteRetrieval(ctx, f.i, lease, next); err != nil {
					t.Fatal(err)
				}
			} else {
				a := log.authority()
				setGoChecksumAuthority(t, f, &a, true)
				revision = 1
				lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "readback-new-source", true)
				if err != nil || !lease.Acquired {
					t.Fatal(err)
				}
				if err = f.s.CompleteRetrieval(ctx, f.i, lease, f.result); err != nil {
					t.Fatal(err)
				}
				if err = f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
					var source int64
					err := tx.QueryRow(ctx, `SELECT source_revision FROM cratectl.artifacts WHERE path LIKE 'go-checksum/%'`).Scan(&source)
					if err == nil && source != 0 {
						t.Error("immutable proof fixture no longer exercises cross-epoch reuse")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", c, revision)
			if err != nil {
				t.Fatal("old retained proof must remain inspectable on its admitted timeline", err)
			}
			marker := verifyStoredGoChecksum(t, f, view)
			if view.Object() != oldView.Object() {
				t.Fatal("unnecessary proof replacement or network recollection")
			}
			if scenario == "consistent-head-growth" {
				if marker.binding != oldMarker.binding {
					t.Fatal("consistent unrelated head growth invalidated unchanged proof receipt")
				}
			} else if marker.binding == oldMarker.binding {
				t.Fatal("new source epoch retained old request admission")
			}
			if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, revision, marker.NativeAdmission()); err != nil {
				t.Fatal(err)
			}
			if scenario == "reused-proof-new-source" {
				if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, revision, oldMarker.NativeAdmission()); err == nil {
					t.Fatal("old source token crossed new epoch")
				}
			}
			encoded, _ := json.Marshal(marker.NativeAdmission())
			if strings.Contains(string(encoded), "GoChecksum") || strings.Contains(string(encoded), "verified") {
				t.Fatal("opaque request token became public JSON")
			}
		})
	}
}

func TestGoModuleChecksumReadbackCannotBorrowAnotherTenantsIdenticalProofToken(t *testing.T) {
	f, log := newGoChecksumIntake(t)
	ctx := context.Background()
	coordinate := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
	if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	approveGoChecksumBundle(t, f)
	first, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", coordinate, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := verifyStoredGoChecksum(t, f, first)
	token, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = Provision(ctx, f.d.OwnerDSN, "proof-other-team", "operator", "admin", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other := f
	other.i, err = f.s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	a := log.authority()
	settings, _ := json.Marshal(RepositorySettings{Upstream: &a.Endpoint, GoChecksumAuthority: &a})
	if err = f.s.Tx(ctx, other.i, true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings) VALUES($1,'owned','go','proxy',true,'restricted',$2)`, other.i.Tenant, settings)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	other.result = other.bundleAtPath(t, coordinate, "assets/inert.txt", log.Payload)
	attachGoChecksum(t, other, &other.result, log.publication(t, "v1.0.0", log.First, 0))
	other.lease, err = f.s.AcquireRetrieval(ctx, other.i, "owned", f.lease.Path, "other-tenant-same-proof", false)
	if err != nil || !other.lease.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, other.i, other.lease, other.result); err != nil {
		t.Fatal(err)
	}
	approveGoChecksumBundle(t, other)
	second, err := f.s.GoModuleChecksumReadback(ctx, other.i, "owned", coordinate, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondToken := verifyStoredGoChecksum(t, other, second)
	control := firstToken.binding
	control.tenant = secondToken.binding.tenant
	if control != secondToken.binding || firstToken.binding.tenant == secondToken.binding.tenant {
		t.Fatal("collision fixture must differ only in tenant; key/heads/proof/bundle/source/lease must match")
	}
	if _, err = f.s.GoModuleProxyArtifact(ctx, other.i, "owned", f.lease.Path, 0, firstToken.NativeAdmission()); !errors.Is(err, ErrGoModuleUnvalidated) {
		t.Fatal("another tenant's identical proof token admitted bytes", err)
	}
	if _, err = f.s.GoModuleProxyArtifact(ctx, other.i, "owned", f.lease.Path, 0, secondToken.NativeAdmission()); err != nil {
		t.Fatal("own tenant's physical proof did not admit exact bytes", err)
	}
}
