// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/configfile"
)

func TestRevokeRejectsOversizedTokenFileBeforeDatabaseConnection(t *testing.T) {
	t.Setenv("CRATECTL_OWNER_DSN", "owned-invalid-connection-fixture")
	path := filepath.Join(t.TempDir(), "cratectl-revoke.token")
	if err := configfile.WriteNewPrivate(path, bytes.Repeat([]byte{'x'}, 258)); err != nil {
		t.Fatal(err)
	}
	previous := os.Args
	os.Args = []string{"cratectld", "revoke", "--token-file", path}
	t.Cleanup(func() { os.Args = previous })
	if err := run(); err == nil || !strings.Contains(err.Error(), "private regular token file within 257 bytes") {
		t.Fatal("oversized credential reached the owner operation", err)
	}
}
