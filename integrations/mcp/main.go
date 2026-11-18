// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ctlplne.dev/cratectl/internal/management"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func run(args []string) error {
	flags := flag.NewFlagSet("cratectl-mcp", flag.ContinueOnError)
	config := flags.String("client-config", "", "absolute path to private cratectl client JSON")
	authority := flags.String("authority", "", "exact expected HTTPS registry authority")
	tenant := flags.String("tenant", "", "expected tenant for all returned metadata")
	consent := flags.Bool("allow-metadata", false, "allow scoped registry metadata to be returned to this local MCP client")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*config) || len(*config) > 4096 ||
		!strings.HasPrefix(*authority, "https://") || !management.ValidRepositoryName(*tenant) || !*consent {
		return errors.New("supply an absolute private client config, exact HTTPS authority, tenant and explicit --allow-metadata")
	}
	registry := &bridge{config: *config, scope: scope{Registry: *authority, Tenant: *tenant}, slots: make(chan struct{}, 4)}
	_, _, closeClient, err := registry.open()
	if err != nil {
		return err
	}
	closeClient()
	server := registry.server()
	return server.Run(context.Background(), &mcp.StdioTransport{MaxLineLength: 64 << 10})
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
