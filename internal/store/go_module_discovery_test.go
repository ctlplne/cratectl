// SPDX-License-Identifier: BUSL-1.1
package store

import "testing"

func TestGoModuleAdvertisementsRetainCachedPolicyAndFirstSourceOwnership(t *testing.T) {
	for _, review := range []bool{false, true} {
		cached := map[string]bool{"v1.0.0": false, "v1.1.0": true}
		addGoModuleAdvertisements(cached, GoModuleCatalog{Versions: []string{"v1.0.0", "v1.1.0", "v1.2.0"}}, review)
		if cached["v1.0.0"] || !cached["v1.1.0"] || cached["v1.2.0"] == review {
			t.Fatal("advertisement overrode cached policy or unknown review", cached, review)
		}
		merged := map[string]bool{}
		mergeGoModuleVersions(merged, cached)
		mergeGoModuleVersions(merged, map[string]bool{"v1.0.0": true, "v1.2.0": true, "v1.3.0": true})
		if merged["v1.0.0"] || merged["v1.2.0"] == review || !merged["v1.3.0"] {
			t.Fatal("lower source replaced blocked/unknown first-source version", merged, review)
		}
	}
}
