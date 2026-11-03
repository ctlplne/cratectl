// SPDX-License-Identifier: BUSL-1.1
package nuget

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strings"
)

const MaxNuspecPropertyBytes = 64 << 10

// Property names are an explicit reader contract, not arbitrary XML-to-model
// deserialization. URL/path/license values are untrusted text and never fetched,
// resolved, interpreted as repository authority or approved as security evidence.
var nuspecPropertyNames = map[string]bool{
	"id": true, "version": true, "authors": true, "owners": true,
	"description": true, "title": true, "summary": true, "tags": true,
	"projecturl": true, "iconurl": true, "licenseurl": true, "language": true,
	"copyright": true, "releasenotes": true, "license": true, "readme": true, "icon": true,
}

type NuspecProperties struct {
	Identity NuspecIdentity    `json:"identity"`
	Values   map[string]string `json:"values"`
}

func propertyName(value string) string {
	for index := range value {
		if value[index] >= 128 {
			return ""
		}
	}
	value = strings.ToLower(value)
	if nuspecPropertyNames[value] {
		return value
	}
	return ""
}

func xmlWhitespace(value []byte) bool {
	for _, b := range value {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return false
		}
	}
	return true
}

// ParseNuspecProperties reads supported scalar metadata after the full bounded
// identity/XML admission. As in GetMetadataValue, nonempty leaf values use the
// first case-insensitive property name, independently of its element namespace.
// Identity, dependency/framework semantics and license evaluation remain separate.
func ParseNuspecProperties(ctx context.Context, raw []byte) (NuspecProperties, error) {
	identity, e := ParseNuspecIdentity(ctx, raw)
	if e != nil {
		return NuspecProperties{}, e
	}
	decoded, _, decoder, e := nuspecDecoder(raw)
	if e != nil {
		return NuspecProperties{}, e
	}
	result := NuspecProperties{Identity: identity, Values: map[string]string{}}
	var names []xml.Name
	var preserve []bool
	active, hasChildren := "", false
	var text strings.Builder
	for count := 0; ; count++ {
		if e := ctx.Err(); e != nil {
			return NuspecProperties{}, e
		}
		if count >= maxNuspecTokens {
			return NuspecProperties{}, ErrNuspec
		}
		before := decoder.InputOffset()
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return NuspecProperties{}, ErrNuspec
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(names) >= maxNuspecDepth {
				return NuspecProperties{}, ErrNuspec
			}
			space := len(preserve) > 0 && preserve[len(preserve)-1]
			for _, attribute := range value.Attr {
				if attribute.Name.Space == "http://www.w3.org/XML/1998/namespace" && attribute.Name.Local == "space" {
					switch attribute.Value {
					case "preserve":
						space = true
					case "default":
						space = false
					default:
						return NuspecProperties{}, ErrNuspec
					}
				}
			}
			if active != "" {
				hasChildren = true
				text.Reset()
			}
			if len(names) == 2 && names[1].Local == "metadata" {
				active, hasChildren = propertyName(value.Name.Local), false
				text.Reset()
			}
			names, preserve = append(names, value.Name), append(preserve, space)
		case xml.EndElement:
			if len(names) == 3 && active != "" {
				if !hasChildren && text.Len() > 0 {
					if _, exists := result.Values[active]; !exists {
						result.Values[active] = text.String()
					}
				}
				active = ""
			}
			names, preserve = names[:len(names)-1], preserve[:len(preserve)-1]
		case xml.CharData:
			if active == "" || hasChildren || len(names) != 3 {
				continue
			}
			original := decoded[before:decoder.InputOffset()]
			explicit := bytes.HasPrefix(original, []byte("<![CDATA[")) || bytes.ContainsRune(original, '&') || preserve[len(preserve)-1]
			if !explicit && xmlWhitespace(value) {
				continue
			}
			if len(value) > MaxNuspecPropertyBytes-text.Len() {
				return NuspecProperties{}, ErrNuspec
			}
			text.Write(value)
		}
	}
	return result, nil
}
