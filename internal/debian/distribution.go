// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"regexp"
	"slices"
	"strings"
)

var distributionSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,63}$`)

// Distribution selects one suite and component with an explicit set of binary
// architectures. A nil distribution uses the existing flat repository layout.
type Distribution struct {
	Suite         string   `json:"suite"`
	Component     string   `json:"component"`
	Architectures []string `json:"architectures"`
}

func (d *Distribution) Valid() bool {
	if d == nil {
		return true
	}
	if !distributionSegment.MatchString(d.Suite) || !distributionSegment.MatchString(d.Component) ||
		len(d.Architectures) < 1 || len(d.Architectures) > 8 {
		return false
	}
	seen := make(map[string]bool, len(d.Architectures))
	for _, arch := range d.Architectures {
		if !architecture.MatchString(arch) || arch == "all" || arch == "any" || arch == "source" || seen[arch] {
			return false
		}
		seen[arch] = true
	}
	return true
}

func (d *Distribution) SupportsArchitecture(arch string) bool {
	return d == nil || arch == "all" || slices.Contains(d.Architectures, arch)
}

func (d *Distribution) IndexArchitectures() []string {
	if d == nil {
		return []string{""}
	}
	return d.Architectures
}

func (d *Distribution) ReleasePath() string {
	if d == nil {
		return "InRelease"
	}
	return "dists/" + d.Suite + "/InRelease"
}

func (d *Distribution) indexPrefix(arch string) string {
	if d == nil {
		return ""
	}
	return d.Component + "/binary-" + arch + "/"
}

func (d *Distribution) IndexPaths(arch string) (string, string) {
	prefix := d.indexPrefix(arch)
	return prefix + "Packages", prefix + "Packages.gz"
}

type IndexRequest struct {
	Architecture string
	Name         string
	SHA256       string
}

func (d *Distribution) ResolveIndex(path string) (IndexRequest, bool) {
	if d == nil {
		return parseIndexRequest("", path)
	}
	for _, arch := range d.Architectures {
		prefix := "dists/" + d.Suite + "/" + d.indexPrefix(arch)
		if remainder, ok := strings.CutPrefix(path, prefix); ok {
			return parseIndexRequest(arch, remainder)
		}
	}
	return IndexRequest{}, false
}

func parseIndexRequest(arch, path string) (IndexRequest, bool) {
	if path == "Packages" || path == "Packages.gz" {
		return IndexRequest{Architecture: arch, Name: path}, true
	}
	if digest, ok := strings.CutPrefix(path, "by-hash/SHA256/"); ok && releaseDigest.MatchString(digest) {
		return IndexRequest{Architecture: arch, SHA256: digest}, true
	}
	return IndexRequest{}, false
}
