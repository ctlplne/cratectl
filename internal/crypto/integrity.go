// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sort"
	"strings"
)

var ErrIntegrity = errors.New("missing, invalid or mismatched source integrity")

func SourceIntegrityFromHex(hashes map[string]string) (SourceIntegrity, error) {
	if len(hashes) > 16 {
		return SourceIntegrity{}, ErrIntegrity
	}
	parts := []string{}
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		value, ok := hashes[algorithm]
		if !ok {
			continue
		}
		decoded, e := hex.DecodeString(value)
		if e != nil {
			return SourceIntegrity{}, ErrIntegrity
		}
		parts = append(parts, algorithm+"-"+base64.StdEncoding.EncodeToString(decoded))
	}
	return ParseSourceIntegrity(strings.Join(parts, " "), "", false)
}
func (s SourceIntegrity) HexHashes() map[string]string {
	if len(s.digests) != 1 {
		return nil
	}
	return map[string]string{s.algorithm: hex.EncodeToString(s.digests[0])}
}

// SourceIntegrity retains only the strongest supported algorithm. Multiple
// digests at that strength are alternatives, as required by SRI. Unknown
// algorithms cannot weaken a supported stronger algorithm.
type SourceIntegrity struct {
	Canonical string
	algorithm string
	digests   [][]byte
}

func ParseSourceIntegrity(raw, legacy string, allowLegacy bool) (SourceIntegrity, error) {
	var out SourceIntegrity
	if len(raw) > 4096 || len(legacy) > 40 {
		return out, ErrIntegrity
	}
	if raw == "" && allowLegacy {
		b, e := hex.DecodeString(legacy)
		if e != nil || len(b) != 20 {
			return out, ErrIntegrity
		}
		raw = "sha1-" + base64.StdEncoding.EncodeToString(b)
	}
	parts := strings.Fields(raw)
	if len(parts) == 0 || len(parts) > 32 {
		return out, ErrIntegrity
	}
	strength := map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}
	if allowLegacy {
		strength["sha1"] = 20
	}
	best := 0
	canonical := map[string][]byte{}
	for _, token := range parts {
		algorithm, value, ok := strings.Cut(token, "-")
		if !ok {
			return out, ErrIntegrity
		}
		n := strength[algorithm]
		if n == 0 {
			continue
		}
		value, _, _ = strings.Cut(value, "?") // SRI options do not change the digest.
		b, e := base64.StdEncoding.DecodeString(value)
		if e != nil {
			b, e = base64.RawStdEncoding.DecodeString(value)
		}
		if e != nil || len(b) != n {
			return out, ErrIntegrity
		}
		if n < best {
			continue
		}
		if n > best {
			canonical = map[string][]byte{}
			best = n
			out.algorithm = algorithm
		}
		canonical[algorithm+"-"+base64.StdEncoding.EncodeToString(b)] = b
	}
	if best == 0 {
		return out, ErrIntegrity
	}
	keys := make([]string, 0, len(canonical))
	for k := range canonical {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.digests = append(out.digests, canonical[k])
	}
	out.Canonical = strings.Join(keys, " ")
	return out, nil
}

func (s SourceIntegrity) Verify(r io.Reader) error {
	var h hash.Hash
	if s.algorithm == "sha384" {
		h = sha512.New384()
	} else {
		h = CompatibilityHash(s.algorithm)
	}
	if h == nil || len(s.digests) == 0 {
		return ErrIntegrity
	}
	if _, e := io.Copy(h, r); e != nil {
		return e
	}
	actual := h.Sum(nil)
	for _, expected := range s.digests {
		if bytes.Equal(actual, expected) {
			return nil
		}
	}
	return ErrIntegrity
}
