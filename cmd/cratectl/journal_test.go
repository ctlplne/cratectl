// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func TestJournalCommandVerifiesPrivateFileWithSeparateCheckpointAndNoPartialReceipt(t *testing.T) {
	payload := `{"tenant":"owned-team","sequence":1,"kind":"owned.fixture","data":{"private":"retained-body"}}`
	event := crypt.JournalEvent{Sequence: 1, Payload: payload, Hash: crypt.Digest([]byte("\n" + payload))}
	page := crypt.JournalPage{Version: 1, Tenant: "owned-team", Through: 1, ThroughHash: event.Hash, Items: []crypt.JournalEvent{event}, NextAfter: 1, NextHash: event.Hash}
	for _, scenario := range []string{"complete", "wrong-head", "wrong-tenant", "missing-head", "missing-file", "public-file", "symlink", "directory", "truncated", "modified", "duplicate-page", "byte-limit", "oversize-budget", "zero-budget", "zero-timeout", "oversize-timeout", "noncanonical-sequence", "extra-argument", "broken-output"} {
		t.Run(scenario, func(t *testing.T) {
			raw, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			switch scenario {
			case "truncated":
				raw = raw[:len(raw)-1]
			case "modified":
				raw = bytes.ReplaceAll(raw, []byte("retained-body"), []byte("changed-body"))
			case "duplicate-page":
				raw = append(raw, raw...)
			}
			path := filepath.Join(t.TempDir(), "journal.jsonl")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "public-file":
				err = os.Chmod(path, 0644)
			case "symlink":
				link := path + ".link"
				err = os.Symlink(path, link)
				path = link
			case "directory":
				path = filepath.Dir(path)
			case "missing-file":
				path += ".absent"
			}
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--export-file", path, "--tenant", "owned-team", "--through", "1", "--through-hash", event.Hash}
			switch scenario {
			case "wrong-head":
				args[7] = strings.Repeat("a", 64)
			case "wrong-tenant":
				args[3] = "another-team"
			case "missing-head":
				args = args[:4]
			case "byte-limit":
				args = append(args, "--max-bytes", "1")
			case "oversize-budget":
				args = append(args, "--max-bytes", "68719476737")
			case "zero-budget":
				args = append(args, "--max-bytes", "0")
			case "zero-timeout":
				args = append(args, "--timeout", "0s")
			case "oversize-timeout":
				args = append(args, "--timeout", "2h")
			case "noncanonical-sequence":
				args[5] = "01"
			case "extra-argument":
				args = append(args, "unexpected")
			}
			var out bytes.Buffer
			var writer io.Writer = &out
			if scenario == "broken-output" {
				writer = checksumBrokenWriter{}
			}
			err = runJournalVerify(args, writer)
			if scenario == "complete" {
				var result struct {
					crypt.JournalVerification
					Trust string
				}
				if err != nil || json.Unmarshal(out.Bytes(), &result) != nil || !result.MatchesSuppliedCheckpoint || result.Events != 1 || result.HeadHash != event.Hash || result.ExportSHA256 != crypt.Digest(raw) || result.Trust == "" || bytes.Contains(out.Bytes(), []byte("retained-body")) {
					t.Fatal("complete range lost checkpoint or leaked original body", err)
				}
			} else if err == nil || out.Len() != 0 {
				t.Fatal("invalid evidence emitted success or partial receipt", err, out.Len())
			}
		})
	}
}
