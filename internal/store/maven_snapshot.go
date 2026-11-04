// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"path"
	"strings"
	"unicode"
)

const MavenSnapshotRedeployNonunique = "redeploy_nonunique"

// Nonunique snapshots use the literal base version in their filename. This
// predicate never admits a release or a timestamp/build-number snapshot.
func MavenNonuniqueSnapshotPath(p string) bool {
	if !materializedLifecyclePath(p) {
		return false
	}
	parts := strings.Split(p, "/")
	if len(parts) < 4 {
		return false
	}
	for _, component := range parts[:len(parts)-1] {
		if !mavenSnapshotComponent(component) {
			return false
		}
	}
	_, _, ok := MavenNonuniqueSnapshotFile(parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1])
	return ok
}

func mavenSnapshotComponent(s string) bool {
	if s == "" || len(s) > 256 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("/\\%?#:<>&\"'", r) {
			return false
		}
	}
	return true
}

// The first dot separates a classifier from an extension, as in the existing
// timestamped snapshot parser. Compound extensions remain one extension.
func MavenNonuniqueSnapshotFile(artifact, version, filename string) (classifier, extension string, ok bool) {
	if !mavenSnapshotComponent(artifact) || !mavenSnapshotComponent(version) || !strings.HasSuffix(version, "-SNAPSHOT") || len(version) <= len("-SNAPSHOT") || len(filename) > 1027 {
		return "", "", false
	}
	// Checksum URLs are derived from their parent and never mutable references.
	switch strings.ToLower(path.Ext(filename)) {
	case ".md5", ".sha1", ".sha256", ".sha384", ".sha512", ".sha-256", ".sha-384", ".sha-512":
		return "", "", false
	}
	prefix := artifact + "-" + version
	if !strings.HasPrefix(filename, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(filename, prefix)
	if strings.HasPrefix(rest, "-") {
		dot := strings.IndexByte(rest, '.')
		if dot < 2 {
			return "", "", false
		}
		classifier, rest = rest[1:dot], rest[dot:]
	}
	if len(rest) < 2 || rest[0] != '.' || !mavenSnapshotComponent(rest[1:]) || classifier != "" && !mavenSnapshotComponent(classifier) {
		return "", "", false
	}
	return classifier, rest[1:], true
}

// Publication rechecks the current repository policy under the tenant write
// lock. Intake-time settings are not authority to replace protected bytes.
func (s *Store) PublishMavenSnapshot(ctx context.Context, i Identity, repo string, a Artifact, sums map[string]string) error {
	if !MavenNonuniqueSnapshotPath(a.Path) {
		return ErrConflict
	}
	return s.replaceNativeReference(ctx, i, repo, a, sums, true)
}
