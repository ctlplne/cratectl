// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

const providerAddress = "ctlplne.dev/ctlplne/cratectl"
const providerVersion = "0.1.0"

func main() {
	options := providerserver.ServeOpts{Address: providerAddress, ProtocolVersion: 6}
	if err := providerserver.Serve(context.Background(), func() provider.Provider { return &cratectlProvider{} }, options); err != nil {
		log.Fatal(err)
	}
}
