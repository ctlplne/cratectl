// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
)

func TestNuGetManifestBindingFailsClosed(t *testing.T) {
	m := NuGetPackage{ID: "Owned.Package", IDKey: "owned.package", IDProfile: nuget.IDKeyProfile, RawVersion: "1.0+owned", VersionKey: "1.0.0", NuspecPath: "Owned.Package.nuspec", Validated: true}
	m.Nuspec = []byte(`<package><metadata><id>Owned.Package</id><version>1.0+owned</version></metadata></package>`)
	m.NuspecSHA256 = crypt.Digest(m.Nuspec)
	a := Artifact{Path: NuGetPath(m.IDKey, m.VersionKey), Digest: crypt.Digest([]byte("parent bytes")), Size: 12, MediaType: "application/octet-stream"}
	a.Metadata, _ = json.Marshal(m)
	if _, e := ValidateNuGetArtifact(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*NuGetPackage){
		func(m *NuGetPackage) { m.Validated = false },
		func(m *NuGetPackage) { m.ID = "Different.Package" },
		func(m *NuGetPackage) { m.IDKey = "Owned.Package" },
		func(m *NuGetPackage) { m.IDProfile = "host-unicode" },
		func(m *NuGetPackage) { m.RawVersion = "2.0" },
		func(m *NuGetPackage) { m.VersionKey = "1.0" },
		func(m *NuGetPackage) { m.Nuspec = append([]byte(nil), m.Nuspec...); m.Nuspec[0] = 'X' },
		func(m *NuGetPackage) { m.NuspecSHA256 = crypt.Digest(nil) },
		func(m *NuGetPackage) { m.NuspecPath = "../owned.nuspec" },
	} {
		bad := m
		change(&bad)
		a.Metadata, _ = json.Marshal(bad)
		if _, e := ValidateNuGetArtifact(context.Background(), a); e == nil {
			t.Fatal("inconsistent manifest identity admitted")
		}
	}
}

func TestNuGetListingDefaultsAndRejectsInvalidState(t *testing.T) {
	var m NuGetPackage
	if !m.IsListed() {
		t.Fatal("existing package became unlisted")
	}
	for _, listed := range []bool{false, true} {
		if e := json.Unmarshal([]byte(`{"listed":`+map[bool]string{true: "true", false: "false"}[listed]+`}`), &m); e != nil || m.IsListed() != listed {
			t.Fatal("listing boolean changed", e)
		}
	}
	for _, bad := range []string{`{"listed":"false"}`, `{"listed":0}`, `{"listed":{}}`} {
		if json.Unmarshal([]byte(bad), &m) == nil {
			t.Fatal("nonboolean listing accepted")
		}
	}
}
