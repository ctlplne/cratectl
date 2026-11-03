// SPDX-License-Identifier: BUSL-1.1
package nuget

import "bytes"

// XML readers replace literal attribute tabs/newlines with spaces, after CRLF
// line-ending normalization. Character references retain their explicit value.
// Normalize only quoted tag attributes: text, comments, CDATA and processing
// instructions must keep their own XML semantics. Original package bytes stay
// untouched. The decoded input is already bounded by decodeNuspec.
func normalizeXMLAttributes(raw []byte) ([]byte, error) {
	if len(raw) > 2*MaxNuspecBytes {
		return nil, ErrNuspec
	}
	var out []byte
	copyThrough := 0
	for pos := 0; pos < len(raw); {
		if raw[pos] != '<' {
			pos++
			continue
		}
		var end []byte
		switch {
		case bytes.HasPrefix(raw[pos:], []byte("<!--")):
			end = []byte("-->")
		case bytes.HasPrefix(raw[pos:], []byte("<![CDATA[")):
			end = []byte("]]>")
		case bytes.HasPrefix(raw[pos:], []byte("<?")):
			end = []byte("?>")
		case bytes.HasPrefix(raw[pos:], []byte("<!")):
			return nil, ErrNuspec // DTDs and other directives are never admitted.
		}
		if end != nil {
			index := bytes.Index(raw[pos:], end)
			if index < 0 {
				return nil, ErrNuspec
			}
			pos += index + len(end)
			continue
		}
		quote := byte(0)
		pos++
		for pos < len(raw) {
			b := raw[pos]
			if quote == 0 {
				if b == '>' {
					pos++
					break
				}
				if b == '\'' || b == '"' {
					quote = b
				}
			} else if b == quote {
				quote = 0
			} else if b == '\t' || b == '\n' || b == '\r' {
				if out == nil {
					out = make([]byte, 0, len(raw))
				}
				out = append(out, raw[copyThrough:pos]...)
				out = append(out, ' ')
				if b == '\r' && pos+1 < len(raw) && raw[pos+1] == '\n' {
					pos++
				}
				copyThrough = pos + 1
			}
			pos++
		}
	}
	if out == nil {
		return raw, nil
	}
	return append(out, raw[copyThrough:]...), nil
}
