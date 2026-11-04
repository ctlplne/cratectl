// SPDX-License-Identifier: BUSL-1.1
// Package crypto is the sole boundary for cryptographic primitives.
package crypto

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1" // npm's legacy shasum is a compatibility checksum, never an authority.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"hash/crc32"
)

func SHA256() hash.Hash { return sha256.New() }

// ZIPCRC32 is a ZIP compatibility checksum, never a content authority.
func ZIPCRC32() hash.Hash32  { return crc32.NewIEEE() }
func Digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func SHA1(b []byte) string   { v := sha1.Sum(b); return hex.EncodeToString(v[:]) }
func Integrity(b []byte) string {
	v := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(v[:])
}
func Token() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CompatibilityHash supports the checksums ordinary Maven clients request.
// SHA-1 and MD5 here do not authorize content; SHA-256 remains the blob identity.
func CompatibilityHash(algorithm string) hash.Hash {
	switch algorithm {
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	case "sha384":
		return sha512.New384()
	case "md5":
		return md5.New()
	}
	return nil
}
