//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/testdb"
	"github.com/jackc/pgx/v5"
	"sync"
	"testing"
	"time"
)

func TestBlankBootstrapAtomicReplayAndRLS(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	if e := Migrate(ctx, d.OwnerDSN); e != nil {
		t.Fatal(e)
	}
	a, _ := crypt.Token()
	w, _ := crypt.Token()
	in := BootstrapInput{InstallationID: crypt.Digest([]byte(a + "installation")), Tenant: "first-team", Actor: "owner", AdminToken: a, WorkerToken: w, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)}
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() { failures <- Bootstrap(ctx, d.OwnerDSN, in) })
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e := pgx.Connect(ctx, d.OwnerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	for table, want := range map[string]int{"tenants": 1, "events": 2, "bootstrap_receipts": 1} {
		var n int
		if e = c.QueryRow(ctx, "SELECT count(*) FROM cratectl."+table).Scan(&n); e != nil || n != want {
			t.Fatalf("%s: %d %v", table, n, e)
		}
	}
	var n int
	if e = c.QueryRow(ctx, `SELECT count(*) FROM cratectl_private.tokens`).Scan(&n); e != nil || n != 2 {
		t.Fatalf("tokens: %d %v", n, e)
	}
	changed := in
	changed.InstallationID = crypt.Digest([]byte("different installation"))
	if e = Bootstrap(ctx, d.OwnerDSN, changed); e == nil {
		t.Fatal("replaced bootstrap receipt")
	}
	changed.Tenant = "other-team"
	if e = Bootstrap(ctx, d.OwnerDSN, changed); e == nil {
		t.Fatal("initialized nonempty database")
	}
	db, e := Open(ctx, d.RuntimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	var seen int
	if e = db.Pool.QueryRow(ctx, `SELECT count(*) FROM cratectl.bootstrap_receipts`).Scan(&seen); e != nil || seen != 0 {
		t.Fatalf("unscoped bootstrap receipt: %d %v", seen, e)
	}
	i, e := db.Authenticate(ctx, a)
	if e != nil || i.Role != "admin" || i.Tenant != in.Tenant {
		t.Fatal("admin credential unavailable")
	}
	if _, e = db.AuthenticateWorker(ctx, w); e != nil {
		t.Fatal("worker credential unavailable")
	}
	if _, e = db.Authenticate(ctx, w); e == nil {
		t.Fatal("worker used public authentication")
	}
	if e = db.Tx(ctx, i, true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE cratectl.bootstrap_receipts SET installation_id=$1`, changed.InstallationID)
		return e
	}); e == nil {
		t.Fatal("runtime changed immutable bootstrap receipt")
	}
}
