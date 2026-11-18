// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"ctlplne.dev/cratectl/internal/configfile"
)

func TestServeRejectsInvalidUpstreamCredentialFilesBeforeDatabaseConnection(t *testing.T) {
	t.Setenv("CRATECTL_DSN", "owned-invalid-connection-fixture")
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	for _, test := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"oversized", bytes.Repeat([]byte{' '}, (64<<10)+1), "private regular upstream credential file within 64 KiB required"},
		{"malformed", []byte(`{"tenant/source":{"value":"owned-inert-test-value"}`), "invalid private upstream credentials JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "upstream.json")
			if err := configfile.WriteNewPrivate(path, test.raw); err != nil {
				t.Fatal(err)
			}
			os.Args = []string{"cratectld", "serve", "--dev-loopback-http", "--public-url", "http://127.0.0.1:38443", "--upstream-credentials", path}
			if err := run(); err == nil || err.Error() != test.want {
				t.Fatal("invalid credential file was accepted or produced an unexpected error", err)
			}
		})
	}
}
