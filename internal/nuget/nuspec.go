// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxNuspecBytes = 1 << 20
const maxNuspecTokens = 32768
const maxNuspecDepth = 32

var ErrNuspec = errors.New("invalid, ambiguous or oversized NuGet manifest identity")
var nuspecEncoding = regexp.MustCompile(`(?i)(?:^|\s)encoding\s*=\s*['"]([^'"]+)['"]`)

// NuspecIdentity preserves declared ID/version text, including whitespace.
// VersionKey alone is normalized. ID key mapping and full package validation
// are separate: the reader's text must never silently become a storage key.
type NuspecIdentity struct {
	ID         string `json:"id"`
	RawVersion string `json:"raw_version"`
	VersionKey string `json:"version_key"`
}

// decodeNuspec accepts UTF-8 and XML UTF-16 with a BOM or byte-order signature.
// Invalid UTF-8, odd UTF-16 lengths and unpaired surrogates are never replaced.
func decodeNuspec(raw []byte) ([]byte, string, error) {
	if len(raw) == 0 || len(raw) > MaxNuspecBytes {
		return nil, "", ErrNuspec
	}
	var order binary.ByteOrder
	hint := "utf-8"
	switch {
	case bytes.HasPrefix(raw, []byte{0xff, 0xfe}):
		order, raw, hint = binary.LittleEndian, raw[2:], "utf-16le"
	case bytes.HasPrefix(raw, []byte{0xfe, 0xff}):
		order, raw, hint = binary.BigEndian, raw[2:], "utf-16be"
	case bytes.HasPrefix(raw, []byte{'<', 0, '?', 0}):
		order, hint = binary.LittleEndian, "utf-16le"
	case bytes.HasPrefix(raw, []byte{0, '<', 0, '?'}):
		order, hint = binary.BigEndian, "utf-16be"
	default:
		raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
		if !utf8.Valid(raw) {
			return nil, "", ErrNuspec
		}
		return raw, hint, nil
	}
	if len(raw)%2 != 0 {
		return nil, "", ErrNuspec
	}
	var decoded strings.Builder
	for index := 0; index < len(raw); index += 2 {
		first := rune(order.Uint16(raw[index:]))
		if first >= 0xd800 && first <= 0xdbff {
			if index+4 > len(raw) {
				return nil, "", ErrNuspec
			}
			second := rune(order.Uint16(raw[index+2:]))
			if second < 0xdc00 || second > 0xdfff {
				return nil, "", ErrNuspec
			}
			decoded.WriteRune(utf16.DecodeRune(first, second))
			index += 2
		} else if first >= 0xdc00 && first <= 0xdfff {
			return nil, "", ErrNuspec
		} else {
			decoded.WriteRune(first)
		}
	}
	return []byte(decoded.String()), hint, nil
}

func validNuspecID(value string) bool {
	if value == "" {
		return false
	}
	units, word := 0, false
	for _, r := range value {
		units++
		if r > 0xffff {
			units++
		}
		if units > 100 {
			return false
		}
		if r == '.' || r == '-' {
			if !word {
				return false
			}
			word = false
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Pc, r) {
			word = true
		} else {
			return false
		}
	}
	return word
}

func nuspecDecoder(raw []byte) ([]byte, string, *xml.Decoder, error) {
	decoded, hint, err := decodeNuspec(raw)
	if err != nil {
		return nil, "", nil, err
	}
	decoded, err = normalizeXMLAttributes(decoded)
	if err != nil {
		return nil, "", nil, err
	}
	decoder := xml.NewDecoder(bytes.NewReader(decoded))
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		label = strings.ToLower(label)
		if strings.HasPrefix(hint, "utf-16") && (label == hint || label == "utf-16") {
			return input, nil // Already decoded after validating every code unit.
		}
		return nil, ErrNuspec
	}
	return decoded, hint, decoder, nil
}

// ParseNuspecIdentity reads only one unambiguous package/metadata/id+version.
// It never resolves external entities, extracts files, executes a package,
// normalizes an ID into a storage key, or declares the full package valid.
func ParseNuspecIdentity(ctx context.Context, raw []byte) (NuspecIdentity, error) {
	var identity NuspecIdentity
	if err := ctx.Err(); err != nil {
		return identity, err
	}
	_, hint, decoder, err := nuspecDecoder(raw)
	if err != nil {
		return identity, err
	}
	var stack []xml.Name
	var namespace, active string
	var text strings.Builder
	root, metadata, declaration := false, false, false
	seen := map[string]bool{}
	for tokens := 0; ; tokens++ {
		if err := ctx.Err(); err != nil {
			return NuspecIdentity{}, err
		}
		if tokens >= maxNuspecTokens {
			return NuspecIdentity{}, ErrNuspec
		}
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return NuspecIdentity{}, ErrNuspec
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) >= maxNuspecDepth || active != "" {
				return NuspecIdentity{}, ErrNuspec
			}
			if len(value.Attr) > 128 {
				return NuspecIdentity{}, ErrNuspec
			}
			attributes := map[xml.Name]bool{}
			for _, attribute := range value.Attr {
				if attributes[attribute.Name] {
					return NuspecIdentity{}, ErrNuspec
				}
				attributes[attribute.Name] = true
			}
			if len(stack) == 0 {
				if root || value.Name.Local != "package" {
					return NuspecIdentity{}, ErrNuspec
				}
				root, namespace = true, value.Name.Space
			}
			if len(stack) == 1 && strings.EqualFold(value.Name.Local, "metadata") {
				if metadata || value.Name.Local != "metadata" || value.Name.Space != namespace {
					return NuspecIdentity{}, ErrNuspec
				}
				metadata = true
			}
			if len(stack) == 2 && stack[1].Local == "metadata" && (strings.EqualFold(value.Name.Local, "id") || strings.EqualFold(value.Name.Local, "version")) {
				field := strings.ToLower(value.Name.Local)
				if value.Name.Local != field || value.Name.Space != namespace || seen[field] {
					return NuspecIdentity{}, ErrNuspec
				}
				seen[field], active = true, field
				text.Reset()
			}
			stack = append(stack, value.Name)
		case xml.EndElement:
			if active != "" && len(stack) == 3 {
				if active == "id" {
					identity.ID = text.String()
				} else {
					identity.RawVersion = text.String()
				}
				active = ""
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(value)) != "" {
				return NuspecIdentity{}, ErrNuspec
			}
			if active != "" {
				limit := MaxVersionBytes
				if active == "id" {
					limit = 400
				}
				if len(value) > limit-text.Len() {
					return NuspecIdentity{}, ErrNuspec
				}
				text.Write(value)
			}
		case xml.Directive:
			return NuspecIdentity{}, ErrNuspec
		case xml.ProcInst:
			if value.Target != "xml" || root || declaration {
				return NuspecIdentity{}, ErrNuspec
			}
			declaration = true
			labels := nuspecEncoding.FindAllSubmatch(value.Inst, -1)
			if len(labels) > 1 {
				return NuspecIdentity{}, ErrNuspec
			}
			if len(labels) == 1 {
				label := strings.ToLower(string(labels[0][1]))
				if label != hint && !(strings.HasPrefix(hint, "utf-16") && label == "utf-16") {
					return NuspecIdentity{}, ErrNuspec
				}
			}
		}
	}
	if !root || !metadata || len(stack) != 0 || !seen["id"] || !seen["version"] || !validNuspecID(strings.TrimSpace(identity.ID)) {
		return NuspecIdentity{}, ErrNuspec
	}
	identity.VersionKey, err = VersionKey(identity.RawVersion)
	if err != nil {
		return NuspecIdentity{}, ErrNuspec
	}
	return identity, nil
}
