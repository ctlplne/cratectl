// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"ctlplne.dev/cratectl/internal/upstream"
	"testing"
)

func TestSignedDeliveryPermissionIsOCIOnly(t *testing.T) {
	for _, format := range []string{"oci", "npm", "pypi", "generic"} {
		for _, where := range []string{"origin", "download", "realm"} {
			t.Run(format+"-"+where, func(t *testing.T) {
				config := upstream.Config{URL: "https://registry.example/v2/", Networks: []string{"0.0.0.0/0"}}
				repo := Repository{Name: "proof", Format: format, Mode: "proxy", Settings: RepositorySettings{Upstream: &config}}
				source := upstream.Config{URL: "https://cdn.example/objects/", Networks: []string{"0.0.0.0/0"}, AllowSignedQuery: true}
				switch where {
				case "origin":
					repo.Settings.Upstream.AllowSignedQuery = true
				case "download":
					repo.Settings.DownloadSources = []upstream.Config{source}
				case "realm":
					repo.Settings.OCITokenEndpoint = &source
					repo.Settings.OCITokenService = "owned"
				}
				e := ValidateRepository(&repo)
				if want := format == "oci" && where != "realm"; (e == nil) != want {
					t.Fatalf("signed delivery authority acceptance=%v wanted=%v", e == nil, want)
				}
			})
		}
	}
}
