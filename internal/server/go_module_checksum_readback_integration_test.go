//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleChecksumPhysicalReadbackAndCurrentGuard(t *testing.T) {
	for _, scenario := range []string{"exact", "corrupt-proof", "missing-proof", "proof-denied-after-readback"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, token, i := schemaServer(t)
			ctx := context.Background()
			c, files := goOriginBytes(t)
			f := goChecksumPublic(t)
			if c.Module != f.Module || c.Version != f.Version {
				t.Fatal("actual inert bundle and public signed fixture differ")
			}
			inspected, err := gomodule.InspectRepresentations(ctx, bytes.NewReader(files["zip"]), int64(len(files["zip"])), c, files["mod"], files["info"], ziparchive.Limits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64})
			if err != nil || inspected.ZIPHash != f.ZIPHash || inspected.GoModHash != f.ModHash {
				t.Fatal("independent actual package h1 binding", err)
			}
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				kind := strings.TrimPrefix(r.URL.Path, "/go/source/"+c.Prefix()+".")
				data, ok := files[kind]
				if !ok {
					w.WriteHeader(404)
					return
				}
				w.Write(data)
			}))
			s.PrivateUpstreamNetworks = []string{"127.0.0.1/32"}
			repo := goCallerRepository(t, s, i, origin.URL, store.CacheSettings{FreshSeconds: 60, StaleSeconds: 60}, false)
			lease, err := s.DB.AcquireRetrieval(ctx, i, repo.Name, c.Prefix()+".zip", "physical-checksum-readback", false)
			if err != nil || !lease.Acquired {
				t.Fatal(err)
			}
			result, err := s.fetchGoModuleBundle(ctx, i, repo, lease)
			if err != nil {
				t.Fatal(err)
			}
			a := store.GoChecksumAuthority{Endpoint: upstream.Config{URL: origin.URL + "/checksum/", Networks: []string{"127.0.0.1/32"}}, VerifierKey: f.Key, InitialCheckpoint: f.Initial, ProofPolicy: &store.GoChecksumProofPolicy{Mode: "retained"}}
			patch, _ := json.Marshal(map[string]any{"go_checksum_authority": a})
			if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE cratectl.repositories SET settings=settings||$1::jsonb WHERE name='source'`, patch)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			proof := store.GoModuleChecksumProof{Profile: store.GoModuleChecksumProfile, Module: c.Module, Version: c.Version, ZIPHash: inspected.ZIPHash, ModHash: inspected.GoModHash, Snapshot: crypt.GoSumDBSnapshot{VerifierKey: f.Key, Checkpoint: f.Initial, Responses: f.Responses}}
			raw, _ := json.Marshal(proof)
			object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(raw), crypt.Digest(raw), int64(len(raw)))
			if err != nil {
				t.Fatal(err)
			}
			result.GoModule.Checksum = &store.GoModuleChecksumPublication{Proof: proof, Object: object, ZIPHash: inspected.ZIPHash, ModHash: inspected.GoModHash, ExpectedCheckpointRevision: 0}
			if err = s.DB.CompleteRetrieval(ctx, i, lease, result); err != nil {
				t.Fatal(err)
			}
			repo, err = s.DB.Repository(ctx, i, repo.Name)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "corrupt-proof" || scenario == "missing-proof" {
				file, err := s.Blobs.Open(i.Tenant, object.Digest)
				if err != nil {
					t.Fatal(err)
				}
				path := file.Name()
				file.Close()
				if scenario == "missing-proof" {
					if err = os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err = os.Chmod(path, 0600); err != nil {
						t.Fatal(err)
					}
					damaged := bytes.Clone(raw)
					damaged[len(damaged)/2] ^= 1
					if err = os.WriteFile(path, damaged, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			admission, err := s.readGoModuleChecksumProof(ctx, i, repo, c)
			if scenario == "corrupt-proof" || scenario == "missing-proof" {
				want := error(blob.ErrIntegrity)
				if scenario == "missing-proof" {
					want = os.ErrNotExist
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(admission, store.NativeAdmission{}) {
					t.Fatal("unavailable physical proof admitted cached bytes", err)
				}
				return
			}
			if err != nil || admission.GoChecksum == nil {
				t.Fatal("actual proof readback did not produce an opaque request admission", err)
			}
			artifact, err := s.DB.GoModuleProxyArtifact(ctx, i, repo.Name, c.Prefix()+".zip", repo.SourceRevision, admission)
			if err != nil {
				t.Fatal(err)
			}
			file, err := s.Blobs.OpenVerified(ctx, i.Tenant, artifact.Digest, artifact.Size)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(file, artifact.Size+1))
			file.Close()
			if err != nil || crypt.Digest(body) != artifact.Digest {
				t.Fatal("exact package disk readback", err)
			}
			want := error(nil)
			if scenario == "proof-denied-after-readback" {
				want = store.ErrDenied
				if err = s.DB.Tx(ctx, i, true, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE cratectl.artifacts SET decision='denied' WHERE path=$1`, "go-checksum/"+object.Digest)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			_, err = s.guardResolved(ctx, i, resolvedArtifact{artifact: artifact, source: repo, admissions: []store.NativeAdmission{admission}})
			if !errors.Is(err, want) {
				t.Fatal("final current guard lost proof policy after physical readback", err)
			}
			if w := goHTTP(t, s, token, "GET", "/go/source/"+c.Prefix()+".zip", nil); w.Code != 405 {
				t.Fatal("internal proof admission enabled unqualified public proxy", w.Code)
			}
		})
	}
}
