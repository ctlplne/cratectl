// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type cratectlProvider struct{}

type providerConfig struct {
	ClientConfig types.String `tfsdk:"client_config"`
}

func (*cratectlProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cratectl"
	resp.Version = providerVersion
}

func (*cratectlProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage cratectl hosted repositories through the tenant-scoped management API.",
		Attributes: map[string]schema.Attribute{
			"client_config": schema.StringAttribute{
				Required:    true,
				Description: "Absolute path to a private cratectl client configuration file on the provider host.",
			},
		},
	}
}

func (*cratectlProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerConfig
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	path := config.ClientConfig.ValueString()
	if config.ClientConfig.IsUnknown() || len(path) > 4096 || !filepath.IsAbs(path) {
		resp.Diagnostics.AddError("Invalid cratectl client configuration", "Supply a known absolute path to a private client configuration file.")
		return
	}
	resp.ResourceData = path
}

func (*cratectlProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{func() resource.Resource { return &hostedRepository{} }}
}

func (*cratectlProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}
