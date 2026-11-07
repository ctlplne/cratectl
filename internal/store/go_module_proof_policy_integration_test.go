//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func ageGoChecksumReceipt(t *testing.T, f goIntakeFixture, seconds int) {
	t.Helper()
	cfg, err := pgx.ParseConfig(f.d.OwnerDSN)
	if err != nil || !strings.HasPrefix(cfg.Database, "cratectl_init_") {
		t.Fatal("receipt clock fault requires a newly owned disposable database")
	}
	ctx := context.Background()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	tag, err := owner.Exec(ctx, `UPDATE cratectl.go_module_checksum_receipts SET created_at=clock_timestamp()+make_interval(secs=>$2) WHERE tenant=$1 AND repository='owned'`, f.i.Tenant, float64(seconds))
	if err != nil || tag.RowsAffected() == 0 {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumProofAgePolicyDoesNotGrantStaleOrHideRefreshableVersions(t *testing.T) {
	for _, scenario := range []string{"retained-old", "recent", "expired", "future", "proof-denied-before-expiry", "proof-retired-before-expiry", "package-denied-before-expiry", "expired-stale", "missing-policy"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			approveGoChecksumBundle(t, f)
			publishChecksumDiscoveryCatalog(t, f, log.Module, "v1.0.0\n")
			a := log.authority()
			if scenario != "retained-old" {
				a.ProofPolicy = &GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}
			}
			if scenario == "missing-policy" {
				a.ProofPolicy = nil
			}
			// Same-epoch owned fault proves current policy checks themselves.
			// Public configuration changes also fence the source epoch.
			setGoChecksumAuthority(t, f, &a, false)
			if scenario != "recent" {
				seconds := -3600
				if scenario == "future" {
					seconds = 3600
				}
				ageGoChecksumReceipt(t, f, seconds)
			}
			want := error(ErrGoChecksumProofExpired)
			admissions := []NativeAdmission{}
			switch scenario {
			case "retained-old", "recent":
				want = nil
			case "proof-denied-before-expiry":
				checksumDiscoveryFault(t, f, `UPDATE cratectl.artifacts SET decision='denied' WHERE starts_with(path,'go-checksum/')`)
				want = ErrDenied
			case "proof-retired-before-expiry":
				checksumDiscoveryFault(t, f, `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,deleted,revision,reason,actor,change_sequence) SELECT tenant,repository,path,digest,true,1,'owned age-policy retirement','operator',1 FROM cratectl.artifacts WHERE starts_with(path,'go-checksum/')`)
				want = ErrDeleted
			case "package-denied-before-expiry":
				checksumDiscoveryFault(t, f, `UPDATE cratectl.artifacts SET decision='denied' WHERE right(path,4)='.zip'`)
				want = ErrDenied
			case "expired-stale":
				checksumDiscoveryFault(t, f, `UPDATE cratectl.retrievals SET state='failed',generation=generation+1,last_error='transient_upstream_failure',stale_until=clock_timestamp()+interval '1 hour' WHERE right(path,4)='.zip'`)
				state, err := f.s.Retrieval(ctx, f.i, "owned", f.lease.Path, 0)
				if err != nil || !state.StalePermitted() {
					t.Fatal("fixture must permit ordinary-origin stale before checksum-age check", err)
				}
				admissions = append(admissions, NativeAdmission{Repository: "owned", Path: state.Path, Generation: state.Generation, Stale: true})
			case "missing-policy":
				want = crypt.ErrGoChecksumAuthority
			}
			coordinate := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
			view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", coordinate, 0, admissions...)
			if !errors.Is(err, want) {
				t.Fatal("current explicit proof age policy", scenario, err, want)
			}
			if err == nil {
				marker := verifyStoredGoChecksum(t, f, view)
				if _, err = f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, 0, marker.NativeAdmission()); err != nil {
					t.Fatal("current admitted proof failed byte guard", err)
				}
			} else if !reflect.DeepEqual(view, GoModuleChecksumReadback{}) {
				t.Fatal("expired/denied proof exposed partial trust")
			}
			if scenario == "retained-old" || scenario == "recent" || scenario == "expired" || scenario == "future" || scenario == "expired-stale" {
				discovery, err := f.s.GoModuleView(ctx, f.i, "owned", log.Module, 100, 1<<20)
				if err != nil || !discovery.Known || !reflect.DeepEqual(discovery.Versions, []string{"v1.0.0"}) {
					t.Fatal("proof age prevented governed refresh routing", err, discovery)
				}
			}
		})
	}
}

func TestGoModuleChecksumProofPolicyIsRecheckedAfterPhysicalReadback(t *testing.T) {
	for _, scenario := range []string{"unchanged", "policy-changed", "expired-after-readback", "future-after-readback"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			a := log.authority()
			a.ProofPolicy = &GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}
			setGoChecksumAuthority(t, f, &a, false)
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			approveGoChecksumBundle(t, f)
			coordinate := gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}
			view, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", coordinate, 0)
			if err != nil {
				t.Fatal(err)
			}
			marker := verifyStoredGoChecksum(t, f, view)
			want := error(nil)
			switch scenario {
			case "policy-changed":
				a.ProofPolicy = &GoChecksumProofPolicy{Mode: "retained"}
				setGoChecksumAuthority(t, f, &a, false)
				want = ErrGoModuleUnvalidated
			case "expired-after-readback":
				ageGoChecksumReceipt(t, f, -3600)
				want = ErrGoChecksumProofExpired
			case "future-after-readback":
				ageGoChecksumReceipt(t, f, 3600)
				want = ErrGoChecksumProofExpired
			}
			artifact, err := f.s.GoModuleProxyArtifact(ctx, f.i, "owned", f.lease.Path, 0, marker.NativeAdmission())
			if !errors.Is(err, want) || err != nil && !reflect.DeepEqual(artifact, Artifact{}) {
				t.Fatal("post-readback proof age/current policy fence", scenario, err, want)
			}
		})
	}
}

func TestGoModuleChecksumExpiredProofRefreshFencesDelayedGeneration(t *testing.T) {
	f, log := newGoChecksumIntake(t)
	ctx := context.Background()
	a := log.authority()
	a.ProofPolicy = &GoChecksumProofPolicy{Mode: "max_age", MaxAgeSeconds: 60}
	setGoChecksumAuthority(t, f, &a, false)
	if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
		t.Fatal(err)
	}
	approveGoChecksumBundle(t, f)
	ageGoChecksumReceipt(t, f, -3600)
	if _, err := f.s.GoModuleChecksumReadback(ctx, f.i, "owned", gomodule.Coordinate{Module: log.Module, Version: "v1.0.0"}, 0); !errors.Is(err, ErrGoChecksumProofExpired) {
		t.Fatal("fixture must observe expired proof in a complete fresh bundle", err)
	}
	observed, err := f.s.Retrieval(ctx, f.i, "owned", f.lease.Path, 0)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.s.AcquireRetrievalRefresh(ctx, f.i, observed, "first-age-refresh", 4, 30*time.Second)
	if err != nil || !lease.Acquired || lease.Generation != observed.Generation+1 {
		t.Fatal("observed generation did not acquire one governed refresh", err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, f.result); err != nil {
		t.Fatal(err)
	}
	delayed, err := f.s.AcquireRetrievalRefresh(ctx, f.i, observed, "delayed-age-refresh", 4, 30*time.Second)
	if err != nil || delayed.Acquired || delayed.Generation != lease.Generation || delayed.State != "ready" {
		t.Fatal("stale proof observation started another forced fill", err)
	}
	head, err := f.s.GoModuleChecksumCheckpoint(ctx, f.i, "owned", 0)
	if err != nil || !bytes.Equal(head.Checkpoint, log.One) || head.Revision != 2 {
		t.Fatal("age refresh reset or advanced identical signed trust", err)
	}
}
