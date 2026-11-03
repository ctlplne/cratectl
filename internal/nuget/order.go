// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"cmp"
	"context"
	"strconv"
	"strings"
)

// These are work/memory ceilings, separate from caller index budgets.
const MaxOrderedVersions = 100000
const MaxOrderedVersionBytes = 64 << 20

type orderedVersion struct {
	key     string
	core    [4]uint32
	release string
}

func orderVersion(raw string) (orderedVersion, error) {
	key, e := VersionKey(raw)
	if e != nil {
		return orderedVersion{}, e
	}
	v := orderedVersion{key: key}
	core, release, _ := strings.Cut(key, "-")
	v.release = release
	for index, part := range strings.Split(core, ".") {
		n, _ := strconv.ParseUint(part, 10, 31) // VersionKey already validated it.
		v.core[index] = uint32(n)
	}
	return v, nil
}

func compareOrdered(left, right orderedVersion) int {
	for index := range left.core {
		if order := cmp.Compare(left.core[index], right.core[index]); order != 0 {
			return order
		}
	}
	if left.release == "" || right.release == "" {
		if left.release == right.release {
			return 0
		}
		if left.release == "" {
			return 1
		}
		return -1
	}
	l, r := left.release, right.release
	for {
		labelL, restL, moreL := strings.Cut(l, ".")
		labelR, restR, moreR := strings.Cut(r, ".")
		// Match the SDK comparer, rather than assuming arbitrary-precision SemVer
		// numbers: signed Int32 labels are numeric; overflow labels are textual.
		numberL, errorL := strconv.ParseInt(labelL, 10, 32)
		numberR, errorR := strconv.ParseInt(labelR, 10, 32)
		order := 0
		switch {
		case errorL == nil && errorR == nil:
			order = cmp.Compare(numberL, numberR)
		case errorL == nil:
			order = -1
		case errorR == nil:
			order = 1
		default:
			order = strings.Compare(labelL, labelR) // Keys already use lowercase ASCII labels.
		}
		if order != 0 {
			return order
		}
		if !moreL || !moreR {
			if moreL == moreR {
				return 0
			}
			if moreL {
				return 1
			}
			return -1
		}
		l, r = restL, restR
	}
}

// CompareVersions compares normalized core/release precedence and ignores build
// metadata. A zero result is an ordering tie, never permission to merge distinct
// VersionKey identities (for example the SDK's signed zero prerelease labels).
func CompareVersions(left, right string) (int, error) {
	l, e := orderVersion(left)
	if e != nil {
		return 0, e
	}
	r, e := orderVersion(right)
	if e != nil {
		return 0, e
	}
	return compareOrdered(l, r), nil
}

// SortVersionKeys returns a stable ascending copy of canonical wire keys. It
// parses each key once, bounds work/memory, and checks cancellation during merges.
// Invalid/noncanonical input never produces a partial list or changes the input.
func SortVersionKeys(ctx context.Context, keys []string) ([]string, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if len(keys) > MaxOrderedVersions {
		return nil, ErrVersion
	}
	bytes := 0
	for _, key := range keys {
		if len(key) > MaxVersionBytes || bytes > MaxOrderedVersionBytes-len(key) {
			return nil, ErrVersion
		}
		bytes += len(key)
	}
	values := make([]orderedVersion, 0, len(keys))
	for _, key := range keys {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		v, e := orderVersion(key)
		if e != nil || v.key != key {
			return nil, ErrVersion
		}
		values = append(values, v)
	}
	buffer := make([]orderedVersion, len(values))
	for width := 1; width < len(values); width *= 2 {
		for start := 0; start < len(values); start += 2 * width {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			middle, end := min(start+width, len(values)), min(start+2*width, len(values))
			left, right := start, middle
			for out := start; out < end; out++ {
				if out%256 == 0 {
					if e := ctx.Err(); e != nil {
						return nil, e
					}
				}
				if right == end || left < middle && compareOrdered(values[left], values[right]) <= 0 {
					buffer[out] = values[left]
					left++
				} else {
					buffer[out] = values[right]
					right++
				}
			}
		}
		values, buffer = buffer, values
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.key
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return result, nil
}
