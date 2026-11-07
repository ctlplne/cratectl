// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCommonExportCommandRefusesIncompleteTrustAndWrongOriginalWithoutReceipt(t *testing.T) {
	fixture := journalSignedCLI(t)
	dir := t.TempDir()
	for name, raw := range map[string][]byte{"journal": fixture.Export, "statement": fixture.Statement, "signature": fixture.Signature, "key": fixture.PublicKey, "manifest": []byte("{}\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := []string{"--manifest-file", filepath.Join(dir, "manifest"), "--set-id", strings.Repeat("c", 64), "--journal-file", filepath.Join(dir, "journal"), "--journal-tenant", fixture.Head.Tenant, "--journal-event-sequence", "1", "--journal-through", strconv.FormatInt(fixture.Head.Sequence, 10), "--journal-through-hash", fixture.Head.Hash}
	trust := []string{"--checkpoint-file", filepath.Join(dir, "statement"), "--checkpoint-signature-file", filepath.Join(dir, "signature"), "--checkpoint-key-file", filepath.Join(dir, "key")}
	for _, scenario := range []string{"empty", "missing-signature", "wrong-original-kind", "noncanonical-event", "trailing-journal", "zero-budget", "public-manifest", "wrong-set"} {
		t.Run(scenario, func(t *testing.T) {
			args := append([]string(nil), base...)
			if scenario != "missing-signature" {
				args = append(args, trust...)
			}
			switch scenario {
			case "empty":
				args = nil
			case "noncanonical-event":
				args = append(args, "--journal-event-sequence", "01")
			case "zero-budget":
				args = append(args, "--journal-max-bytes", "0")
			case "trailing-journal":
				p := filepath.Join(dir, "trailing")
				if err := os.WriteFile(p, append(bytes.Clone(fixture.Export), []byte("{}\n")...), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--journal-file", p)
			case "public-manifest":
				p := filepath.Join(dir, "public")
				if err := os.WriteFile(p, []byte("{}\n"), 0644); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--manifest-file", p)
			case "wrong-set":
				args = append(args, "--set-id", "invalid")
			}
			var out bytes.Buffer
			if err := runGoExportSetVerify(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid complete trust returned receipt", scenario, err)
			}
		})
	}
}
