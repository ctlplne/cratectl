// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"os"
	"path/filepath"
	"testing"

	"ctlplne.dev/cratectl/internal/configfile"
)

func TestWorkerRefusesNonregularIdentityConfigurationBeforeDatabase(t *testing.T) {
	t.Setenv("CRATECTL_DSN", "owned-invalid-connection-fixture")
	directory := filepath.Join(t.TempDir(), "identities")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	os.Args = []string{"cratectld", "worker", "--identities", directory}
	if err := run(); err == nil || err.Error() != "worker identity configuration requires a bounded private regular file" {
		t.Fatal("nonregular worker identity configuration was not refused at the file boundary", err)
	}
}

func TestWorkerIdentityConfigurationPreservesExactBudgetAndClosedObject(t *testing.T) {
	const valid = `{"token_files":["worker.token"]}`
	for _, test := range []struct {
		name, input string
		limit       int
		accepted    bool
	}{
		{"exact", valid, len(valid), true},
		{"one-extra-byte", valid + " ", len(valid), false},
		{"second-object", valid + " {}", len(valid) + 3, false},
		{"unknown-field", `{"token_files":[],"unexpected":true}`, 128, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "worker.json")
			if err := configfile.WriteNewPrivate(path, []byte(test.input)); err != nil {
				t.Fatal(err)
			}
			files, err := workerTokenFiles(path, int64(test.limit))
			if test.accepted {
				if err != nil || len(files) != 1 || files[0] != "worker.token" {
					t.Fatal("exact private worker identity object was not retained", err)
				}
			} else if err == nil {
				t.Fatal("invalid worker identity object accepted")
			}
		})
	}
}
