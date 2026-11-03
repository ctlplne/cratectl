// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCatalogBindsDiscoveryToSelectedMetadata(t *testing.T) {
	for _, tc := range []struct {
		version, deps string
		pre, sem2     bool
	}{
		{"1.0", "", false, false}, {"1.0-rc", "", true, false}, {"1.0-rc.1", "", true, true}, {"1.0+Owned", "", false, true},
		{"1.0", `<dependency id="Owned.Dep" version="[1.0-rc.1,2.0)"/>`, false, true},
		{"1.0", `<dependency id="Owned.Dep" version="[1.0+Owned,2.0)"/>`, false, true},
	} {
		raw := []byte(`<package><metadata><id>Owned.Package</id><version>` + tc.version + `</version><description>First</description><description>Later</description><requireLicenseAcceptance>TrUe</requireLicenseAcceptance><dependencies>` + tc.deps + `</dependencies></metadata></package>`)
		c, e := BuildCatalog(context.Background(), raw)
		if e != nil || c.Profile != CatalogProfile || c.Prerelease != tc.pre || c.SemVer2 != tc.sem2 || c.Values["description"] != "First" || c.Values["requirelicenseacceptance"] != "TrUe" || c.SourceSHA != "" {
			t.Fatal(c, e)
		}
		if tc.version == "1.0+Owned" && c.Version != "1.0.0+Owned" {
			t.Fatal("lost build metadata", c.Version)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, e := BuildCatalog(ctx, []byte(`<package/>`)); !errors.Is(e, context.Canceled) || c.Profile != "" {
		t.Fatal("cancel returned usable catalog", c, e)
	}
}

func TestCatalogOrderKeyPreservesSDKPrecedenceTies(t *testing.T) {
	values := []string{"1", "2", "10", "1.0.0.1", "2147483647", "1-rc.2", "1-rc.10", "1-alpha", "1-alpha.0", "1-alpha-", "1--0", "1-0", "1--01", "1--1", "1--2147483648", "1--2147483649", "1-2147483648", "1-10000000000"}
	for _, left := range values {
		for _, right := range values {
			order, e := CompareVersions(left, right)
			l, le := VersionOrderKey(left)
			r, re := VersionOrderKey(right)
			if e != nil || le != nil || re != nil || strings.Compare(l, r) != order {
				t.Fatal("byte order changed precedence", left, right, order, l, r, e, le, re)
			}
		}
	}
}
