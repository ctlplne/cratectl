// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"errors"
	"slices"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
)

func TestGoModuleCacheReceiptsBindWholeCurrentBundle(t *testing.T) {
	c := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/cache", Version: "v1.0.0"}
	repo := Repository{Name: "source", Format: "go", Mode: "proxy", SourceRevision: 7}
	receipts := []Retrieval{}
	for _, kind := range []string{"zip", "mod", "info"} {
		receipts = append(receipts, Retrieval{Repository: repo.Name, Path: c.Prefix() + "." + kind, State: "failed", Generation: 3, SourceRevision: 7, ValidationRoot: c.Prefix() + ".zip", ValidationGeneration: 2})
	}
	if e := validateGoModuleCacheReceipts(repo, c, receipts); e != nil {
		t.Fatal("last complete generation should survive a newer refresh attempt", e)
	}
	for _, scenario := range []string{"missing", "order", "source", "repository", "path", "root", "generation", "future-generation", "unbound-root", "no-generation", "ready-old-generation"} {
		t.Run(scenario, func(t *testing.T) {
			rs := slices.Clone(receipts)
			want := ErrGoModuleUnvalidated
			switch scenario {
			case "missing":
				rs = rs[:2]
			case "order":
				rs[0], rs[1] = rs[1], rs[0]
			case "source":
				rs[1].SourceRevision--
				want = ErrSourceChanged
			case "repository":
				rs[1].Repository = "other"
				want = ErrSourceChanged
			case "path":
				rs[1].Path = c.Prefix() + ".zip"
				want = ErrSourceChanged
			case "root":
				rs[1].ValidationRoot = "other"
			case "generation":
				rs[1].ValidationGeneration++
			case "future-generation":
				rs[0].ValidationGeneration = 4
			case "unbound-root":
				rs[0].ValidationRoot = "other"
			case "no-generation":
				rs[0].ValidationGeneration = 0
			case "ready-old-generation":
				rs[0].State = "ready"
			}
			if e := validateGoModuleCacheReceipts(repo, c, rs); !errors.Is(e, want) {
				t.Fatal("invalid bundle cache receipt admitted", scenario, e)
			}
		})
	}
}
