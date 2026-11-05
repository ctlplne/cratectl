// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestGoModulePreparationRejectsInvalidInputBeforeEffects(t *testing.T) {
	for _, test := range []struct {
		name, module string
		limit        int
		budget       int64
		want         error
	}{
		{"empty", "", 100, 4096, store.ErrGoModuleUnvalidated},
		{"invalid", "bad", 100, 4096, store.ErrGoModuleUnvalidated},
		{"alias", "go.cratectl.invalid/!owned", 100, 4096, store.ErrGoModuleUnvalidated},
		{"long", "go.cratectl.invalid/" + strings.Repeat("a", 4096), 100, 4096, store.ErrGoModuleUnvalidated},
		{"no-versions", "go.cratectl.invalid/owned", 0, 4096, store.ErrMetadataLimit},
		{"many-versions", "go.cratectl.invalid/owned", 10001, 4096, store.ErrMetadataLimit},
		{"no-bytes", "go.cratectl.invalid/owned", 100, 0, store.ErrMetadataLimit},
		{"many-bytes", "go.cratectl.invalid/owned", 100, 64<<20 + 1, store.ErrMetadataLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := New(nil, nil, "")
			s.NativeVersionLimit = test.limit
			s.NativeMetadataBytes = test.budget
			view, admissions, e := s.prepareGoModuleView(context.Background(), store.Identity{}, store.Repository{Name: "owned", Format: "go"}, test.module, false)
			if !errors.Is(e, test.want) || view.Known || len(view.Versions) != 0 || len(admissions) != 0 {
				t.Fatal("invalid preparation admitted effects or partial view", e)
			}
		})
	}
}
