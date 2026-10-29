//go:build integration && (darwin || linux)

// SPDX-License-Identifier: BUSL-1.1
package installation

import (
	"context"
	"ctlplne.dev/cratectl/internal/configfile"
	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializationResumesPreparationAndCommittedDatabase(t *testing.T) {
	d := testdb.New(t)
	dir := filepath.Join(t.TempDir(), "installation")
	o := Options{Directory: dir, Tenant: "first-team", OwnerDSN: d.OwnerDSN, RuntimeDSN: d.RuntimeDSN}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Initialize(ctx, o); e == nil {
		t.Fatal("cancelled initialization succeeded")
	}
	var p preparation
	if e := configfile.Read(filepath.Join(dir, "prepare.json"), &p); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "runtime.json")); !os.IsNotExist(e) {
		t.Fatal("published runtime configuration before database initialization")
	}
	receipt, e := Initialize(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(dir, "prepare.json"))
	if e != nil {
		t.Fatal(e)
	}
	// The database is already committed. Simulate a crash before ready config
	// publication and prove the original preparation replays without token churn.
	if e = os.Remove(receipt.RuntimeConfig); e != nil {
		t.Fatal(e)
	}
	again, e := Initialize(context.Background(), Options{Directory: dir, OwnerDSN: d.OwnerDSN})
	if e != nil || again.InstallationID != receipt.InstallationID {
		t.Fatalf("resume committed DB: %v", e)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "prepare.json"))
	if string(after) != string(before) {
		t.Fatal("resume changed credentials or trust")
	}
	c, e := pgx.Connect(context.Background(), d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	var count int
	if e = c.QueryRow(context.Background(), `SELECT count(*) FROM cratectl_private.tokens`).Scan(&count); e != nil || count != 2 {
		t.Fatalf("credential churn: %d %v", count, e)
	}
	if e = os.WriteFile(filepath.Join(dir, "admin.token"), []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Initialize(context.Background(), o); e == nil {
		t.Fatal("overwrote modified credential file")
	}
	bytes, _ := os.ReadFile(filepath.Join(dir, "admin.token"))
	if string(bytes) != "changed" {
		t.Fatal("modified credential file was lost")
	}
}
