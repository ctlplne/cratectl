//go:build integration

// SPDX-License-Identifier: BUSL-1.1
// Package testdb owns disposable databases within the cratectl test cluster.
package testdb

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"testing"
	"time"
)

type Database struct{ OwnerDSN, RuntimeDSN string }

func New(t *testing.T) Database {
	t.Helper()
	owner, e := pgx.ParseConfig(os.Getenv("CRATECTL_OWNER_DSN"))
	if e != nil || os.Getenv("CRATECTL_OWNER_DSN") == "" {
		t.Fatal("real owned database owner configuration required")
	}
	runtime, e := pgx.ParseConfig(os.Getenv("CRATECTL_DSN"))
	if e != nil || os.Getenv("CRATECTL_DSN") == "" {
		t.Fatal("real runtime database configuration required")
	}
	token, e := crypt.Token()
	if e != nil {
		t.Fatal(e)
	}
	name := "cratectl_init_" + crypt.Digest([]byte(token))[:16]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, e := pgx.ConnectConfig(ctx, owner)
	if e != nil {
		t.Fatal("connect owned fixture cluster")
	}
	defer c.Close(ctx)
	if _, e = c.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, e := pgx.ConnectConfig(ctx, owner)
		if e != nil {
			t.Error("connect for owned fixture cleanup")
			return
		}
		defer c.Close(ctx)
		if _, e = c.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error(e)
		}
	})
	withDatabase := func(dsn string) string {
		u, e := url.Parse(dsn)
		if e == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
			u.Path = "/" + name
			u.RawPath = ""
			return u.String()
		}
		return dsn + " dbname=" + name
	}
	return Database{OwnerDSN: withDatabase(owner.ConnString()), RuntimeDSN: withDatabase(runtime.ConnString())}
}
