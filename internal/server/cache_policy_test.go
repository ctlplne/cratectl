// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"ctlplne.dev/cratectl/internal/store"
	"net/http"
	"testing"
)

func TestSourceFreshnessCannotExpandConfiguredBudget(t *testing.T) {
	repo := store.Repository{Settings: store.RepositorySettings{Cache: store.CacheSettings{FreshSeconds: 300, StaleSeconds: 60}}}
	for _, c := range []struct {
		header, age  string
		fresh, stale int
		denied       bool
	}{{"max-age=60", "20", 40, 60, false}, {"max-age=600", "", 300, 60, false}, {"no-cache, max-age=600", "", 0, 0, false}, {"max-age=60, must-revalidate", "", 60, 0, false}, {"max-age=60", "invalid", 0, 60, false}, {"no-store", "", 0, 0, true}} {
		h := http.Header{}
		h.Set("Cache-Control", c.header)
		h.Set("Age", c.age)
		fresh, stale, e := cachePolicy(h, repo, store.Retrieval{}, 200)
		if (e != nil) != c.denied || (!c.denied && (fresh != c.fresh || stale != c.stale)) {
			t.Fatalf("freshness case %q gave %d/%d, err=%v", c.header, fresh, stale, e)
		}
	}
	fresh, stale, e := cachePolicy(http.Header{}, repo, store.Retrieval{SourceFresh: 0, SourceStale: 0}, 304)
	if e != nil || fresh != 0 || stale != 0 {
		t.Fatal("304 expanded a prior no-cache policy")
	}
}
