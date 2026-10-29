// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"ctlplne.dev/cratectl/internal/configfile"
	"ctlplne.dev/cratectl/internal/installation"
	"encoding/json"
	"flag"
	"os"
	"time"
)

func runInit() error {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := f.String("directory", "", "new private native installation directory, or the same directory to resume")
	tenant := f.String("tenant", "", "first tenant name; required for a new installation")
	actor := f.String("actor", "", "first administrator name; defaults to operator")
	listen := f.String("listen", "", "loopback listener; defaults to 127.0.0.1:38443")
	public := f.String("public-url", "", "HTTPS loopback authority; defaults to https://localhost:38443")
	lifetime := f.Duration("credential-lifetime", 0, "administrator and worker lifetime; defaults to 24h")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	receipt, e := installation.Initialize(ctx, installation.Options{Directory: *dir, Tenant: *tenant, Actor: *actor, Listen: *listen, PublicURL: *public, Lifetime: *lifetime, OwnerDSN: os.Getenv("CRATECTL_OWNER_DSN"), RuntimeDSN: os.Getenv("CRATECTL_DSN")})
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(receipt)
}
func runtimeConfiguration(path string) (configfile.Runtime, error) {
	var c configfile.Runtime
	if e := configfile.Read(path, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func flagSet(f *flag.FlagSet) map[string]bool {
	m := map[string]bool{}
	f.Visit(func(v *flag.Flag) { m[v.Name] = true })
	return m
}
