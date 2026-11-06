//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func publishChecksumDiscoveryCatalog(t *testing.T, f goIntakeFixture, mod, versions string) {
	t.Helper()
	ctx := context.Background()
	data := []byte(versions)
	catalog, err := NewGoModuleCatalog(mod, data, 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	object, err := f.objects.Put(ctx, f.i.Tenant, bytes.NewReader(data), "", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleCatalogPath(mod), "checksum-discovery-catalog", false)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Status: 200, Object: &object, Metadata: raw, MediaType: GoModuleCatalogMedia, GoCatalog: &catalog, FreshSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	// Latest may consult this optional hint when every tag is blocked. Its
	// explicit current absence must not erase a known package's ownership.
	hint, err := f.s.AcquireRetrieval(ctx, f.i, "owned", GoModuleLatestPath(mod), "checksum-discovery-no-latest", false)
	if err != nil || !hint.Acquired {
		t.Fatal(err)
	}
	if err = f.s.CompleteRetrieval(ctx, f.i, hint, RetrievalResult{Status: 404, FreshSeconds: 60}); err != nil {
		t.Fatal(err)
	}
}

func checksumDiscoveryFault(t *testing.T, f goIntakeFixture, sql string) {
	t.Helper()
	if err := f.s.Tx(context.Background(), f.i, true, func(tx pgx.Tx) error { _, err := tx.Exec(context.Background(), sql); return err }); err != nil {
		t.Fatal(err)
	}
}

func TestGoModuleChecksumDiscoveryRequiresCurrentReceiptKeyAndProofPolicy(t *testing.T) {
	for _, scenario := range []string{"valid", "expired", "refreshing", "refreshing-fork", "ready-error", "transient", "fork", "unverified", "negative", "package-denied", "package-unreviewed", "proof-denied", "proof-digest-decision", "proof-retired", "proof-media", "proof-metadata", "proof-metadata-key", "proof-digest", "proof-size", "raw-zip-binding", "raw-mod-binding", "raw-info-binding", "validation-generation", "root", "sibling-generation", "sibling-source", "package-epoch", "current-key", "required-unconfigured", "missing-head", "proof-oversized-metadata", "aggregate-budget"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			approveGoChecksumBundle(t, f)
			publishChecksumDiscoveryCatalog(t, f, log.Module, "v1.0.0\n")
			want := []string{}
			wantErr := error(nil)
			budget := int64(1 << 20)
			sql := ""
			switch scenario {
			case "valid":
				want = []string{"v1.0.0"}
			case "expired":
				want = []string{"v1.0.0"}
				sql = `UPDATE cratectl.retrievals SET fresh_until='epoch',stale_until='epoch' WHERE right(path,4)='.zip'`
			case "refreshing":
				want = []string{"v1.0.0"}
				sql = `UPDATE cratectl.retrievals SET state='fetching',generation=generation+1,fresh_until='epoch' WHERE right(path,4)='.zip'`
			case "refreshing-fork":
				sql = `UPDATE cratectl.retrievals SET state='fetching',generation=generation+1,last_error='upstream_checksum_fork' WHERE right(path,4)='.zip'`
			case "ready-error":
				sql = `UPDATE cratectl.retrievals SET last_error='upstream_checksum_unverified' WHERE right(path,4)='.zip'`
			case "transient":
				want = []string{"v1.0.0"}
				sql = `UPDATE cratectl.retrievals SET state='failed',generation=generation+1,last_error='transient_upstream_failure',stale_until='epoch' WHERE right(path,4)='.zip'`
			case "fork":
				sql = `UPDATE cratectl.retrievals SET state='failed',last_error='upstream_checksum_fork' WHERE right(path,4)='.zip'`
			case "unverified":
				sql = `UPDATE cratectl.retrievals SET state='failed',last_error='upstream_checksum_unverified' WHERE right(path,4)='.zip'`
			case "negative":
				sql = `UPDATE cratectl.retrievals SET state='negative',last_status=404 WHERE right(path,4)='.zip'`
			case "package-denied":
				sql = `UPDATE cratectl.artifacts SET decision='denied' WHERE right(path,4)='.mod'`
			case "package-unreviewed":
				sql = `UPDATE cratectl.artifacts SET decision='unassessed' WHERE right(path,5)='.info'`
			case "proof-denied":
				sql = `UPDATE cratectl.artifacts SET decision='denied' WHERE starts_with(path,'go-checksum/')`
			case "proof-digest-decision":
				// A current digest decision must prevail even if the reference
				// projection is deliberately left with its old allowed value.
				sql = `INSERT INTO cratectl.content_decisions(tenant,repository,digest,decision) SELECT tenant,repository,digest,'denied' FROM cratectl.artifacts WHERE starts_with(path,'go-checksum/')`
			case "proof-retired":
				sql = `INSERT INTO cratectl.artifact_lifecycle(tenant,repository,path,digest,deleted,revision,reason,actor,change_sequence) SELECT tenant,repository,path,digest,true,1,'owned discovery retirement','operator',1 FROM cratectl.artifacts WHERE starts_with(path,'go-checksum/')`
			case "proof-media":
				sql = `UPDATE cratectl.artifacts SET media_type='application/octet-stream' WHERE starts_with(path,'go-checksum/')`
			case "proof-metadata":
				sql = `UPDATE cratectl.artifacts SET metadata='{}' WHERE starts_with(path,'go-checksum/')`
			case "proof-metadata-key":
				sql = `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{go_checksum_key_digest}',to_jsonb(repeat('0',64))) WHERE starts_with(path,'go-checksum/')`
			case "proof-digest":
				sql = `UPDATE cratectl.artifacts SET digest=repeat('0',64) WHERE starts_with(path,'go-checksum/')`
			case "proof-size":
				sql = `UPDATE cratectl.artifacts SET size=size+1 WHERE starts_with(path,'go-checksum/')`
			case "raw-zip-binding", "raw-mod-binding", "raw-info-binding":
				kind := strings.TrimSuffix(strings.TrimPrefix(scenario, "raw-"), "-binding")
				// Keep all three package manifests internally consistent while
				// changing one raw identity beneath its immutable checksum receipt.
				sql = `UPDATE cratectl.artifacts SET metadata=jsonb_set(metadata,'{representations_sha256,` + kind + `}',to_jsonb(repeat('0',64))),digest=CASE WHEN path LIKE '%.` + kind + `' THEN repeat('0',64) ELSE digest END WHERE starts_with(path,'go.cratectl.invalid/')`
			case "validation-generation":
				sql = `UPDATE cratectl.retrievals SET generation=generation+1,validation_generation=validation_generation+1 WHERE right(path,4)='.zip'`
			case "root":
				sql = `UPDATE cratectl.retrievals SET validation_root=path||'.other' WHERE right(path,4)='.zip'`
			case "sibling-generation":
				sql = `UPDATE cratectl.retrievals SET generation=generation+1,validation_generation=validation_generation+1 WHERE right(path,4)='.mod'`
			case "sibling-source":
				sql = `UPDATE cratectl.retrievals SET source_revision=source_revision+1 WHERE right(path,5)='.info'`
			case "package-epoch":
				sql = `UPDATE cratectl.artifacts SET source_revision=source_revision+1 WHERE starts_with(path,'go.cratectl.invalid/')`
				// The current catalog remains routing metadata. Under review it
				// cannot approve versions whose package epoch is no longer current.
			case "current-key":
				other, _, _ := checksumPublicFixture(t)
				setGoChecksumAuthority(t, f, &other, false)
			case "required-unconfigured":
				sql = `UPDATE cratectl.repositories SET settings=(settings-'go_checksum_authority')||'{"cache":{"require_checksum":true}}'::jsonb WHERE name='owned'`
			case "missing-head":
				cfg, err := pgx.ParseConfig(f.d.OwnerDSN)
				if err != nil || !strings.HasPrefix(cfg.Database, "cratectl_init_") {
					t.Fatal("head fault requires newly owned disposable database")
				}
				owner, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				_, err = owner.Exec(ctx, `DELETE FROM cratectl.go_checksum_checkpoints WHERE tenant=$1`, f.i.Tenant)
				owner.Close(ctx)
				if err != nil {
					t.Fatal(err)
				}
				wantErr = crypt.ErrGoChecksumAuthority
			case "proof-oversized-metadata":
				sql = `UPDATE cratectl.artifacts SET metadata=metadata||jsonb_build_object('owned-padding',repeat('x',4097)) WHERE starts_with(path,'go-checksum/')`
				wantErr = ErrMetadataLimit
			case "aggregate-budget":
				// Three bundle rows fit; trust/proof/catalog must share the
				// remaining complete-view budget rather than each resetting it.
				budget = 3000
				wantErr = ErrMetadataLimit
			}
			if sql != "" {
				checksumDiscoveryFault(t, f, sql)
			}
			for _, latest := range []bool{false, true} {
				var view GoModuleVersionView
				var err error
				if latest {
					view, err = f.s.GoModuleLatestView(ctx, f.i, "owned", log.Module, 100, budget)
				} else {
					view, err = f.s.GoModuleView(ctx, f.i, "owned", log.Module, 100, budget)
				}
				if !errors.Is(err, wantErr) {
					t.Fatal("checksum discovery witness", scenario, latest, err, wantErr)
				}
				if err != nil {
					if view.Known || len(view.Versions) != 0 {
						t.Fatal("failed discovery exposed a partial view")
					}
				} else if !view.Known || !reflect.DeepEqual(view.Versions, want) {
					t.Fatal("checksum discovery lost ownership/policy", scenario, latest, view, want)
				}
			}
		})
	}
}

func TestGoModuleChecksumDiscoveryRetainsHistoricalProofAcrossGrowthAndSourceEpoch(t *testing.T) {
	for _, scenario := range []string{"head-growth", "source-epoch"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			want := []string{"v1.0.0"}
			if scenario == "head-growth" {
				result := f.bundleAtPath(t, gomodule.Coordinate{Module: log.Module, Version: "v1.1.0"}, "assets/inert.txt", log.Payload)
				attachGoChecksum(t, f, &result, log.publication(t, "v1.1.0", log.Second, 2))
				lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", result.GoModule.Objects[0].Path, "discovery-head-growth", false)
				if err != nil || !lease.Acquired {
					t.Fatal(err)
				}
				if err = f.s.CompleteRetrieval(ctx, f.i, lease, result); err != nil {
					t.Fatal(err)
				}
				want = append(want, "v1.1.0")
			} else {
				a := log.authority()
				setGoChecksumAuthority(t, f, &a, true)
				lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "discovery-source-epoch", true)
				if err != nil || !lease.Acquired {
					t.Fatal(err)
				}
				if err = f.s.CompleteRetrieval(ctx, f.i, lease, f.result); err != nil {
					t.Fatal(err)
				}
				if err = f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
					var source int64
					err := tx.QueryRow(ctx, `SELECT source_revision FROM cratectl.artifacts WHERE starts_with(path,'go-checksum/')`).Scan(&source)
					if err == nil && source != 0 {
						t.Error("fixture no longer exercises original proof across epochs")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			approveGoChecksumBundle(t, f)
			publishChecksumDiscoveryCatalog(t, f, log.Module, strings.Join(want, "\n")+"\n")
			for _, latest := range []bool{false, true} {
				var view GoModuleVersionView
				var err error
				if latest {
					view, err = f.s.GoModuleLatestView(ctx, f.i, "owned", log.Module, 100, 1<<20)
				} else {
					view, err = f.s.GoModuleView(ctx, f.i, "owned", log.Module, 100, 1<<20)
				}
				if err != nil || !view.Known || !reflect.DeepEqual(view.Versions, want) {
					t.Fatal("current discovery lost immutable accepted history/proof", scenario, view, err)
				}
			}
			view, err := f.s.GoModuleView(ctx, f.i, "owned", log.Module, len(want)-1, 1<<20)
			if !errors.Is(err, ErrMetadataLimit) || view.Known || len(view.Versions) != 0 {
				t.Fatal("bounded complete view exposed partial version set", err)
			}
		})
	}
}

func TestGoModuleChecksumDiscoveryBlockedFirstSourceShadowsLowerAndCatalog(t *testing.T) {
	for _, scenario := range []string{"proof-denied", "required-unconfigured", "namespace-owner", "unknown-advertisement", "group-review"} {
		t.Run(scenario, func(t *testing.T) {
			f, log := newGoChecksumIntake(t)
			ctx := context.Background()
			if err := f.s.CompleteRetrieval(ctx, f.i, f.lease, f.result); err != nil {
				t.Fatal(err)
			}
			approveGoChecksumBundle(t, f)
			versions := "v1.0.0\n"
			if scenario == "unknown-advertisement" || scenario == "group-review" {
				versions += "v1.2.0\n"
			}
			publishChecksumDiscoveryCatalog(t, f, log.Module, versions)
			settings := RepositorySettings{Members: []string{"owned", "lower"}}
			if scenario == "namespace-owner" {
				settings.NamespaceOwners = map[string]string{"go.cratectl.invalid/!owned/": "lower"}
			}
			if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
				if err := CreateRepository(ctx, tx, f.i, Repository{Name: "lower", Format: "go", Access: "restricted"}); err != nil {
					return err
				}
				return CreateRepository(ctx, tx, f.i, Repository{Name: "combined", Format: "go", Mode: "group", Access: "restricted", RequireReview: scenario == "group-review", Settings: settings})
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.PublishGoModule(ctx, f.i, "lower", f.result.GoModule.Objects, "lower-checksum-discovery"); err != nil {
				t.Fatal(err)
			}
			checksumDiscoveryFault(t, f, `UPDATE cratectl.artifacts SET decision='allowed' WHERE repository='lower'`)
			checksumDiscoveryFault(t, f, `UPDATE cratectl.repositories SET require_review=false WHERE name='owned'`)
			checksumDiscoveryFault(t, f, `UPDATE cratectl.artifacts SET decision='denied' WHERE repository='owned' AND starts_with(path,'go-checksum/')`)
			if scenario == "required-unconfigured" {
				checksumDiscoveryFault(t, f, `UPDATE cratectl.repositories SET settings=(settings-'go_checksum_authority')||'{"cache":{"require_checksum":true}}'::jsonb WHERE name='owned'`)
			}
			view, err := f.s.GoModuleView(ctx, f.i, "combined", log.Module, 100, 1<<20)
			want := []string{}
			if scenario == "namespace-owner" {
				want = []string{"v1.0.0"}
			} else if scenario == "unknown-advertisement" {
				want = []string{"v1.2.0"}
			}
			if err != nil || !view.Known || !reflect.DeepEqual(view.Versions, want) {
				t.Fatal("blocked first source fell through catalog/lower source", scenario, view, err)
			}
			if scenario == "unknown-advertisement" {
				if _, err := f.s.GoModuleProxyArtifact(ctx, f.i, "owned", strings.Replace(f.lease.Path, "v1.0.0", "v1.2.0", 1), f.lease.SourceRevision); !errors.Is(err, ErrGoModuleUnvalidated) {
					t.Fatal("routing advertisement became checksum byte admission", err)
				}
			}
		})
	}
}
