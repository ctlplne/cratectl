// SPDX-License-Identifier: BUSL-1.1
// Package nuget contains shared native NuGet protocol contracts. It does not
// publish, extract, execute, or deserialize the contents of a package.
package nuget

import (
	"errors"
	"strconv"
	"strings"
)

// MaxVersionBytes bounds input and normalized output, including input build metadata.
// This is an input safety budget, not a claim that NuGet limits versions to
// this length or that all repository adapters have been implemented.
const MaxVersionBytes = 1024

var ErrVersion = errors.New("invalid or oversized NuGet version")

// VersionKey returns the lowercase, normalized package-base-address identity.
// NuGet accepts one to four numeric components (each a nonnegative Int32),
// pads to three components, omits a zero revision, ignores build metadata for
// identity, and compares prerelease labels without regard to ASCII case.
// Ranges and floating versions belong to dependency resolution, not this key.
func VersionKey(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > MaxVersionBytes {
		return "", ErrVersion
	}
	raw = strings.TrimSpace(raw)
	version, metadata, hasMetadata := strings.Cut(raw, "+")
	if hasMetadata && !validLabels(metadata, true) {
		return "", ErrVersion
	}
	core, release, hasRelease := strings.Cut(version, "-")
	if hasRelease && !validLabels(release, false) {
		return "", ErrVersion
	}
	parts := strings.Split(core, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return "", ErrVersion
	}
	var numbers [4]uint64
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if !digits(part) {
			return "", ErrVersion
		}
		number, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return "", ErrVersion
		}
		numbers[index] = number
	}
	count := 3
	if numbers[3] != 0 {
		count = 4
	}
	normalized := make([]string, count)
	for index := range normalized {
		normalized[index] = strconv.FormatUint(numbers[index], 10)
	}
	key := strings.Join(normalized, ".")
	if hasRelease {
		key += "-" + strings.ToLower(release)
	}
	if len(key) > MaxVersionBytes {
		return "", ErrVersion
	}
	return key, nil
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validLabels(value string, metadata bool) bool {
	for _, label := range strings.Split(value, ".") {
		if label == "" || !metadata && len(label) > 1 && label[0] == '0' && digits(label) {
			return false
		}
		for index := range label {
			c := label[index]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
