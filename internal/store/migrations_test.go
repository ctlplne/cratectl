// SPDX-License-Identifier: BUSL-1.1
package store

import "testing"

func TestAppliedMigrationDefinitionsStayImmutable(t *testing.T) {
	// Appending a step is allowed. Changing one of these requires a separate new
	// migration, rather than invalidating the receipts of deployed databases.
	expected := []string{
		"1e0f7b93d872f8ab83f85742000a6282f2722a0a338d8f2bc81755345ba66d16",
		"9e023c96c8cf33549ce81f1eac22551b5cdb6267d146f65d430ec254dc8b10b5",
	}
	steps := currentMigrations()
	for n, checksum := range expected {
		if len(steps) <= n || steps[n].Version != n+1 || hashMigration(steps[n]) != checksum {
			t.Fatalf("applied migration %d changed; append a new immutable step", n+1)
		}
	}
	steps[0].SQL = "modified by caller"
	if hashMigration(currentMigrations()[0]) != expected[0] {
		t.Fatal("caller changed the immutable plan")
	}
}
