// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxReleaseBytes = 128 << 10

var ErrRelease = errors.New("invalid Debian flat repository InRelease envelope")

var releaseDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type IndexDigest struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Release struct {
	Issued     time.Time              `json:"issued"`
	ValidUntil time.Time              `json:"valid_until"`
	Indexes    map[string]IndexDigest `json:"indexes"`
}

func GzipIndex(index []byte) ([]byte, error) {
	var buffer bytes.Buffer
	encoded := gzip.NewWriter(&buffer)
	if _, err := encoded.Write(index); err != nil {
		return nil, err
	}
	if err := encoded.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (r Release) Active(now time.Time) bool {
	return !r.Issued.IsZero() && r.Issued.Before(r.ValidUntil) && r.ValidUntil.After(now) && !r.Issued.After(now.Add(10*time.Second))
}

// ParseInRelease binds the cleartext digest entries to a bounded envelope.
// APT verifies the OpenPGP signature using its independently configured key.
func ParseInRelease(data []byte) (Release, error) {
	if len(data) == 0 || len(data) > MaxReleaseBytes || !utf8.Valid(data) {
		return Release{}, ErrRelease
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.ContainsAny(text, "\r\x00") {
		return Release{}, ErrRelease
	}
	const header = "-----BEGIN PGP SIGNED MESSAGE-----\n"
	const signatureStart = "\n-----BEGIN PGP SIGNATURE-----\n"
	const signatureEnd = "\n-----END PGP SIGNATURE-----"
	clear, ok := strings.CutPrefix(text, header)
	if !ok {
		return Release{}, ErrRelease
	}
	hash, clear, ok := strings.Cut(clear, "\n\n")
	if !ok || (hash != "Hash: SHA256" && hash != "Hash: SHA384" && hash != "Hash: SHA512") {
		return Release{}, ErrRelease
	}
	stanza, signature, ok := strings.Cut(clear, signatureStart)
	if !ok || !validSignatureArmor(signature, signatureEnd) {
		return Release{}, ErrRelease
	}
	return parseRelease(stanza)
}

func validSignatureArmor(signature, end string) bool {
	blocks, ok := strings.CutSuffix(strings.TrimRight(signature, "\n"), end)
	if !ok {
		return false
	}
	_, payload, ok := strings.Cut("\n"+blocks, "\n\n")
	if !ok {
		return false
	}
	if data, checksum, found := strings.Cut(payload, "\n="); found {
		decoded, err := base64.StdEncoding.Strict().DecodeString(checksum)
		if err != nil || len(decoded) != 3 {
			return false
		}
		payload = data
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
	return err == nil && len(decoded) > 0
}

func parseRelease(stanza string) (Release, error) {
	out := Release{Indexes: map[string]IndexDigest{}}
	fields := map[string]bool{}
	last := ""
	for line := range strings.SplitSeq(strings.TrimRight(stanza, "\n"), "\n") {
		if len(line) == 0 || len(line) > 4096 || strings.HasPrefix(line, "- ") {
			return Release{}, ErrRelease
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" || last == "date" || last == "valid-until" {
				return Release{}, ErrRelease
			}
			if last != "sha256" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 3 || !releaseDigest.MatchString(parts[0]) || (parts[2] != "Packages" && parts[2] != "Packages.gz") {
				return Release{}, ErrRelease
			}
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if _, duplicate := out.Indexes[parts[2]]; duplicate || err != nil || size < 0 || size > 8<<20 {
				return Release{}, ErrRelease
			}
			out.Indexes[parts[2]] = IndexDigest{SHA256: parts[0], Size: size}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || !fieldName.MatchString(key) || len(fields) >= 64 {
			return Release{}, ErrRelease
		}
		last = strings.ToLower(key)
		if fields[last] {
			return Release{}, ErrRelease
		}
		fields[last] = true
		value = strings.TrimSpace(value)
		var err error
		switch last {
		case "date":
			out.Issued, err = releaseTime(value)
		case "valid-until":
			out.ValidUntil, err = releaseTime(value)
		case "sha256":
			if value != "" {
				return Release{}, ErrRelease
			}
		}
		if err != nil {
			return Release{}, ErrRelease
		}
	}
	if out.Issued.IsZero() || !out.Issued.Before(out.ValidUntil) || len(out.Indexes) != 2 {
		return Release{}, ErrRelease
	}
	return out, nil
}

func releaseTime(value string) (time.Time, error) {
	if strings.HasSuffix(value, " UTC") || strings.HasSuffix(value, " GMT") {
		return time.Parse(time.RFC1123, value)
	}
	return time.Parse(time.RFC1123Z, value)
}
