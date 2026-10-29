// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

// CursorKey is separate from TLS and credentials. Operators share it across
// replicas and rotate it before 2^32 seals, the GCM random-nonce key-use limit.
type CursorKey struct{ aead cipher.AEAD }

func ParseCursorKey(secret string) (*CursorKey, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(secret)
	if e != nil || len(b) != 32 {
		return nil, errors.New("pagination key must encode 32 random bytes")
	}
	defer clear(b)
	block, e := aes.NewCipher(b)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCMWithRandomNonce(block)
	if e != nil {
		return nil, e
	}
	return &CursorKey{aead}, nil
}
func (k *CursorKey) Seal(scope, position string, before bool) (string, error) {
	if k == nil || len(position) == 0 || len(position) > 2048 || len(scope) > 8192 {
		return "", errors.New("invalid pagination position")
	}
	data := append([]byte{0}, []byte(position)...)
	if before {
		data[0] = 1
	}
	return "p1." + base64.RawURLEncoding.EncodeToString(k.aead.Seal(nil, nil, data, []byte(scope))), nil
}
func (k *CursorKey) Open(scope, token string) (string, bool, error) {
	invalid := errors.New("invalid or differently scoped pagination cursor")
	if k == nil || len(token) > 3000 || !strings.HasPrefix(token, "p1.") || len(scope) > 8192 {
		return "", false, invalid
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, "p1."))
	if e != nil {
		return "", false, invalid
	}
	data, e := k.aead.Open(nil, nil, b, []byte(scope))
	if e != nil || len(data) < 2 || len(data) > 2049 || data[0] > 1 {
		return "", false, invalid
	}
	return string(data[1:]), data[0] == 1, nil
}
