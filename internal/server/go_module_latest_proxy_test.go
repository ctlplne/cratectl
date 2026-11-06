// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestGoModuleOriginLatestPreservesBoundedOriginalCoordinateAdvertisement(t *testing.T) {
	for _, scenario := range []string{"release", "pseudo", "bad-version", "ambiguous", "bad-time", "raw-budget", "combined-budget", "not-found", "no-cache", "bare304"} {
		t.Run(scenario, func(t *testing.T) {
			c, _ := goOriginBytes(t)
			data := []byte("{\n \"Version\":\"v1.0.0\", \"Origin\":{\"URL\":\"https://never-follow.invalid/ignored\"}\n}\n")
			if scenario == "pseudo" {
				data = []byte(`{"Time":"2026-01-02T03:04:05Z","Version":"v0.0.0-20260102030405-0123456789ab"}`)
			}
			if scenario == "bad-version" {
				data = []byte(`{"Version":"v2.0.0"}`)
			}
			if scenario == "ambiguous" {
				data = []byte(`{"Version":"v1.0.0","version":"v1.0.0"}`)
			}
			if scenario == "bad-time" {
				data = []byte(`{"Version":"v0.0.0-20260102030405-0123456789ab","Time":"2026-01-02T03:04:06Z"}`)
			}
			var calls atomic.Int32
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/go/source/"+strings.TrimPrefix(store.GoModuleLatestPath(c.Module), "go-latest/")+"/@latest" || r.Header.Get("Authorization") != "Bearer owned-origin-token" || r.Header.Get("If-None-Match") != "" {
					t.Error("latest escaped configured source or full-body request")
					w.WriteHeader(400)
					return
				}
				if scenario == "not-found" {
					w.WriteHeader(404)
					return
				}
				if scenario == "bare304" {
					w.WriteHeader(304)
					return
				}
				w.Header().Set("Cache-Control", "max-age=17, must-revalidate")
				if scenario == "no-cache" {
					w.Header().Add("Cache-Control", "no-cache")
				}
				w.Write(data)
			}))
			s, i, repo, lease := goOriginFixture(t, origin.URL, c)
			lease.Path = store.GoModuleLatestPath(c.Module)
			repo.Settings.Cache.RequireChecksum = true // names do not satisfy package checksum policy
			if scenario == "raw-budget" {
				s.NativeMetadataBytes = 4
			}
			if scenario == "combined-budget" {
				s.NativeMetadataBytes = int64(len(data))
			}
			result, e := s.fetchGoModuleLatest(context.Background(), i, repo, lease)
			if calls.Load() != 1 {
				t.Fatal("latest retried or contacted another source", calls.Load())
			}
			if scenario != "release" && scenario != "pseudo" && scenario != "no-cache" {
				if e == nil || result.Object != nil || result.GoLatest != nil || len(result.Metadata) != 0 {
					t.Fatal("invalid latest exposed partial intake", e)
				}
				if scenario == "not-found" && !errors.Is(e, errGoModuleOriginMissing) {
					t.Fatal("latest missing lost origin classification", e)
				}
				return
			}
			fresh := 17
			if scenario == "no-cache" {
				fresh = 0
			}
			if e != nil || result.GoLatest == nil || result.Object == nil || result.GoModule != nil || result.GoCatalog != nil || result.FreshSeconds != fresh || result.StaleSeconds != 0 {
				t.Fatal("latest lost original coordinate/cache binding", e)
			}
			a := store.Artifact{Path: lease.Path, Digest: result.Object.Digest, Size: result.Object.Size, MediaType: result.MediaType, Metadata: result.Metadata}
			if _, e = store.ValidateGoModuleLatestArtifact(a); e != nil {
				t.Fatal(e)
			}
			f, e := s.Blobs.OpenVerified(context.Background(), i.Tenant, a.Digest, a.Size)
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(f)
			f.Close()
			if e != nil || !bytes.Equal(got, data) {
				t.Fatal("latest original response bytes changed", e)
			}
		})
	}
}
