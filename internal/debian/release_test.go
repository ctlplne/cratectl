// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseInReleaseChecksActiveScopeAndExactIndexEntries(t *testing.T) {
	before := time.Date(2026, 11, 19, 3, 1, 0, 0, time.UTC)
	after := before.Add(time.Hour)
	zero, one := strings.Repeat("0", 64), strings.Repeat("1", 64)
	text := fmt.Sprintf("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nDate: %s\nValid-Until: %s\nSHA256:\n %s 0 Packages\n %s 17 Packages.gz\n-----BEGIN PGP SIGNATURE-----\n\nT3BhcXVlIGZpeHR1cmU=\n-----END PGP SIGNATURE-----\n",
		before.Format(time.RFC1123), after.Format(time.RFC1123), zero, one)
	// The synthetic armor exercises envelope parsing. Stock APT verification
	// has a separate fixture with a generated key and a real signature.
	value, err := ParseInRelease([]byte(text))
	if err != nil || value.Indexes["Packages"] != (IndexDigest{SHA256: zero}) ||
		value.Indexes["Packages.gz"] != (IndexDigest{SHA256: one, Size: 17}) || !value.Active(before) || value.Active(after) {
		t.Fatal("bad release binding or expiry", value, err)
	}
	for _, invalid := range []string{
		strings.Replace(text, "Hash: SHA256", "Hash: SHA1", 1),
		strings.Replace(text, "17 Packages.gz", "17 Sources.gz", 1),
		strings.Replace(text, "17 Packages.gz", "17 Packages", 1),
		strings.Replace(text, "T3BhcXVlIGZpeHR1cmU=", "not armor", 1),
		strings.Replace(text, "SHA256:\n", "SHA256:\n\n", 1),
	} {
		if _, err := ParseInRelease([]byte(invalid)); !errors.Is(err, ErrRelease) {
			t.Fatal("accepted an invalid Debian release envelope", err)
		}
	}
}
