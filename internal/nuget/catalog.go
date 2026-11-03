// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const CatalogProfile = "nuspec-catalog-v1"

// Catalog is a rebuildable discovery projection. SourceSHA binds it to the
// retained manifest; it never supplies authorization or a security decision.
type Catalog struct {
	Profile    string            `json:"profile"`
	SourceSHA  string            `json:"source_sha256"`
	Version    string            `json:"version"`
	Order      string            `json:"order"`
	Prerelease bool              `json:"prerelease"`
	SemVer2    bool              `json:"semver2"`
	Values     map[string]string `json:"values"`
}

// VersionOrderKey sorts like CompareVersions under PostgreSQL's C collation.
// Ordering ties deliberately remain ties: coordinate identity is a separate key.
func VersionOrderKey(raw string) (string, error) {
	v, e := orderVersion(raw)
	if e != nil {
		return "", e
	}
	var key strings.Builder
	for _, number := range v.core {
		fmt.Fprintf(&key, "%010d!", number)
	}
	if v.release == "" {
		key.WriteByte('2')
	} else {
		key.WriteByte('1')
		for _, label := range strings.Split(v.release, ".") {
			if n, e := strconv.ParseInt(label, 10, 32); e == nil {
				fmt.Fprintf(&key, "0%010d!", n+2147483648)
			} else {
				key.WriteByte('1')
				key.WriteString(label)
				key.WriteByte('!') // Below every permitted label character.
			}
		}
	}
	return key.String(), nil
}

func semVer2Version(raw string) bool {
	version, _, metadata := strings.Cut(raw, "+")
	_, release, _ := strings.Cut(version, "-")
	return metadata || strings.Contains(release, ".")
}

func BuildCatalog(ctx context.Context, raw []byte) (Catalog, error) {
	p, e := ParseNuspecProperties(ctx, raw)
	if e != nil {
		return Catalog{}, e
	}
	d, e := ParseNuspecDependencies(ctx, raw)
	if e != nil {
		return Catalog{}, e
	}
	order, e := VersionOrderKey(p.Identity.VersionKey)
	if e != nil {
		return Catalog{}, e
	}
	version := p.Identity.VersionKey
	if _, metadata, present := strings.Cut(strings.TrimSpace(p.Identity.RawVersion), "+"); present {
		version += "+" + metadata
	}
	if len(version) > MaxVersionBytes {
		return Catalog{}, ErrVersion
	}
	c := Catalog{Profile: CatalogProfile, Version: version, Order: order, Prerelease: strings.Contains(p.Identity.VersionKey, "-"), SemVer2: semVer2Version(p.Identity.RawVersion), Values: p.Values}
	for _, group := range d.Groups {
		for _, dep := range group.Dependencies {
			c.SemVer2 = c.SemVer2 || strings.Contains(dep.RawRange, "+") || semVer2Version(dep.Range.Min) || semVer2Version(dep.Range.Max)
		}
	}
	return c, nil
}
