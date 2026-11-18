// SPDX-License-Identifier: BUSL-1.1
package cargo

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

const (
	MediaType        = "application/x-cargo-crate"
	MaxUploadBytes   = 64 << 20
	MaxMetadataBytes = 1 << 20
	MaxIndexBytes    = 256 << 10
)

var (
	ErrInput = errors.New("invalid or unsupported Cargo package input")
	ErrLimit = errors.New("Cargo package input exceeds its reviewed bounds")

	namePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	reserved    = regexp.MustCompile(`^(aux|con|nul|prn|com[1-9]|lpt[1-9])$`)
	core        = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+]|$)`)
)

func NameKey(name string) (string, error) {
	key := strings.ToLower(name)
	if !namePattern.MatchString(name) || reserved.MatchString(key) {
		return "", ErrInput
	}
	return key, nil
}

// VersionKey removes build metadata for the uniqueness rule used by indexes.
// Cargo still receives the complete original version from the index.
func VersionKey(version string) (string, error) {
	if len(version) > 128 || !semver.IsValid("v"+version) {
		return "", ErrInput
	}
	match := core.FindStringSubmatch(version)
	if len(match) != 4 {
		return "", ErrInput
	}
	for _, number := range match[1:] {
		if _, err := strconv.ParseUint(number, 10, 64); err != nil {
			return "", ErrInput
		}
	}
	key, _, _ := strings.Cut(version, "+")
	return key, nil
}

func IndexPath(name string) (string, error) {
	key, err := NameKey(name)
	if err != nil {
		return "", err
	}
	switch len(key) {
	case 1, 2:
		return strconv.Itoa(len(key)) + "/" + key, nil
	case 3:
		return "3/" + key[:1] + "/" + key, nil
	default:
		return key[:2] + "/" + key[2:4] + "/" + key, nil
	}
}

func ArtifactPrefix(name string) (string, error) {
	key, err := NameKey(name)
	if err != nil {
		return "", err
	}
	return "crates/" + strings.ReplaceAll(key, "_", "-") + "/", nil
}

func ArtifactPath(name, version string) (string, error) {
	prefix, err := ArtifactPrefix(name)
	if err != nil {
		return "", err
	}
	key, err := VersionKey(version)
	if err != nil {
		return "", err
	}
	return prefix + key + ".crate", nil
}
