// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/management"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*hostedRepository)(nil)
	_ resource.ResourceWithConfigure   = (*hostedRepository)(nil)
	_ resource.ResourceWithImportState = (*hostedRepository)(nil)
	_ resource.ResourceWithModifyPlan  = (*hostedRepository)(nil)
)

type hostedRepository struct {
	providerSettings
}

type repositoryState struct {
	ID            types.String `tfsdk:"id"`
	Tenant        types.String `tfsdk:"tenant"`
	Name          types.String `tfsdk:"name"`
	Format        types.String `tfsdk:"format"`
	Access        types.String `tfsdk:"access"`
	RequireReview types.Bool   `tfsdk:"require_review"`
	Authority     types.String `tfsdk:"authority"`
	StateScope    types.String `tfsdk:"state_scope"`
	State         types.String `tfsdk:"lifecycle_state"`
	StateRevision types.Int64  `tfsdk:"lifecycle_revision"`
}

func (s repositoryState) spec() management.RepositorySpec {
	return management.RepositorySpec{
		Name: s.Name.ValueString(), Format: s.Format.ValueString(), Access: s.Access.ValueString(),
		RequireReview: s.RequireReview.ValueBool(),
	}
}

func (s repositoryState) inputsKnown() bool {
	return !s.Tenant.IsUnknown() && !s.Name.IsUnknown() && !s.Format.IsUnknown() &&
		!s.Access.IsUnknown() && !s.RequireReview.IsUnknown() && !s.Authority.IsUnknown()
}

func (s repositoryState) valid() bool {
	return management.ValidRepositoryName(s.Tenant.ValueString()) && s.spec().Valid() && !s.RequireReview.IsNull() && s.Authority.ValueString() != ""
}

func (s *repositoryState) observe(current *management.RepositoryObservation) {
	s.Format = types.StringValue(current.Format)
	s.Access = types.StringValue(current.Access)
	s.RequireReview = types.BoolValue(current.RequireReview)
	s.State = types.StringValue(current.State)
	s.StateRevision = types.Int64Value(current.StateRevision)
}

func (*hostedRepository) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hosted_repository"
}

func (*hostedRepository) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	reuse := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "Create or import a hosted repository. Registry-managed lifecycle state and revision are refreshed for review.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, PlanModifiers: reuse, Description: "Repository identity in TENANT/NAME form.",
			},
			"tenant": schema.StringAttribute{
				Required: true, Description: "Tenant of the expected current administrator.",
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Repository name in this tenant.",
			},
			"format": schema.StringAttribute{
				Required: true, Description: "Supported hosted format (generic, maven, npm, pypi, oci, nuget or go).",
			},
			"access": schema.StringAttribute{
				Required: true, Description: "Repository access, tenant or restricted.",
			},
			"require_review": schema.BoolAttribute{
				Required: true, Description: "Require an artifact decision before delivery.",
			},
			"authority": schema.StringAttribute{
				Required: true, Description: "Exact configured registry authority, including the HTTPS scheme and any explicit port.",
			},
			"state_scope": schema.StringAttribute{
				Computed: true, PlanModifiers: reuse, Description: "Provider state scope used to bind creation retries.",
			},
			"lifecycle_state": schema.StringAttribute{
				Computed: true, Description: "Current retained repository state, including suspended or removed.",
			},
			"lifecycle_revision": schema.Int64Attribute{
				Computed: true, Description: "Current retained repository lifecycle revision.",
			},
		},
	}
}

func (r *hostedRepository) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	config, ok := req.ProviderData.(providerSettings)
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "The cratectl provider did not supply a private client configuration path.")
		return
	}
	r.providerSettings = config
}

func (r *hostedRepository) open(ctx context.Context, tenant, expectedAuthority string) (*management.Repositories, []string, error) {
	remote, err := management.OpenRepositories(r.configPath)
	if err != nil {
		return nil, nil, err
	}
	if expectedAuthority != "" && remote.Authority() != expectedAuthority {
		remote.Close()
		return nil, nil, errors.New("the client configuration authority differs from the bound repository authority")
	}
	formats, err := remote.Authorize(ctx, tenant)
	if err != nil {
		remote.Close()
		return nil, nil, err
	}
	return remote, formats, nil
}

func (*hostedRepository) immutable(diagnostics *diag.Diagnostics) {
	diagnostics.AddError("Hosted repository settings require operator review",
		"Manage retained lifecycle and source settings through cratectl. Review any change to tenant, name, format, access or review policy before updating configuration and importing verified state.")
}

func (*hostedRepository) protected(diagnostics *diag.Diagnostics) {
	diagnostics.AddError("Repository retirement requires a cratectl operator",
		"The repository and its artifacts are retained. Detach the Terraform/OpenTofu state only after confirming the intended repository identity.")
}

func (r *hostedRepository) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		r.protected(&resp.Diagnostics)
		return
	}
	var planned repositoryState
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planned)...)
	if resp.Diagnostics.HasError() || !planned.inputsKnown() {
		return
	}
	if !planned.valid() {
		resp.Diagnostics.AddError("Invalid hosted repository configuration", "Supply a valid tenant, repository name, hosted format, access and review requirement.")
		return
	}
	if !req.State.Raw.IsNull() {
		var prior repositoryState
		resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
		if !resp.Diagnostics.HasError() && (prior.Tenant != planned.Tenant || prior.Authority != planned.Authority || prior.spec() != planned.spec()) {
			r.immutable(&resp.Diagnostics)
		}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	remote, formats, err := r.open(ctx, planned.Tenant.ValueString(), planned.Authority.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to plan hosted repository", err.Error())
		return
	}
	defer remote.Close()
	if !slices.Contains(formats, planned.Format.ValueString()) {
		resp.Diagnostics.AddError("Hosted format unavailable", "The authenticated registry does not serve the configured format.")
		return
	}
	current, err := remote.Inspect(ctx, planned.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect hosted repository", err.Error())
		return
	}
	if current != nil {
		resp.Diagnostics.AddWarning("Repository already retained", "Review the existing repository. An unrelated prior creation requires explicit tenant/name import.")
	}
	planned.StateScope = types.StringValue(r.stateScope)
	planned.ID = types.StringValue(planned.Tenant.ValueString() + "/" + planned.Name.ValueString())
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &planned)...)
}

func (r *hostedRepository) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var planned repositoryState
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planned)...)
	if resp.Diagnostics.HasError() {
		return
	}
	spec := planned.spec()
	tenant := planned.Tenant.ValueString()
	if !planned.inputsKnown() || !planned.valid() || !management.ValidRepositoryName(r.stateScope) ||
		planned.StateScope.ValueString() != r.stateScope || planned.ID.ValueString() != tenant+"/"+spec.Name {
		resp.Diagnostics.AddError("Invalid hosted repository plan", "Review a new plan before creating the repository.")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	remote, formats, err := r.open(ctx, tenant, planned.Authority.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to authorize repository creation", err.Error())
		return
	}
	defer remote.Close()
	if !slices.Contains(formats, spec.Format) {
		resp.Diagnostics.AddError("Hosted format unavailable", "The authenticated registry does not serve the planned format.")
		return
	}
	key := crypto.Digest([]byte(strings.Join([]string{r.stateScope, planned.Authority.ValueString(), tenant, spec.Name}, "\n")))
	if err := remote.Create(ctx, spec, "terraform-repository-"+key); err != nil {
		resp.Diagnostics.AddError("Repository creation was not confirmed", err.Error())
		return
	}
	current, err := remote.Inspect(ctx, spec.Name)
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify created repository", err.Error())
		return
	}
	if current == nil || current.Mode != "hosted" || current.State != "active" || current.RepositorySpec != spec {
		resp.Diagnostics.AddError("Created repository differs from its plan", "Inspect the retained repository before applying or importing again.")
		return
	}
	planned.observe(current)
	resp.Diagnostics.Append(resp.State.Set(ctx, &planned)...)
}

func (r *hostedRepository) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var saved repositoryState
	resp.Diagnostics.Append(req.State.Get(ctx, &saved)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.read(ctx, &saved, &resp.Diagnostics, func() diag.Diagnostics { return resp.State.Set(ctx, &saved) })
}

func (r *hostedRepository) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tenant, name, found := strings.Cut(req.ID, "/")
	if !found || !management.ValidRepositoryName(tenant) || !management.ValidRepositoryName(name) {
		resp.Diagnostics.AddError("Invalid repository import identity", "Use the existing repository's TENANT/NAME.")
		return
	}
	saved := repositoryState{ID: types.StringValue(req.ID), Tenant: types.StringValue(tenant), Name: types.StringValue(name)}
	r.read(ctx, &saved, &resp.Diagnostics, func() diag.Diagnostics { return resp.State.Set(ctx, &saved) })
}

func (r *hostedRepository) read(ctx context.Context, saved *repositoryState, diagnostics *diag.Diagnostics, save func() diag.Diagnostics) {
	if scope := saved.StateScope.ValueString(); scope != "" && scope != r.stateScope {
		diagnostics.AddError("Repository state scope changed", "Restore the provider state scope bound to the saved repository.")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	remote, _, err := r.open(ctx, saved.Tenant.ValueString(), saved.Authority.ValueString())
	if err != nil {
		diagnostics.AddError("Unable to authorize repository inspection", err.Error())
		return
	}
	defer remote.Close()
	current, err := remote.Inspect(ctx, saved.Name.ValueString())
	if err != nil {
		diagnostics.AddError("Unable to inspect hosted repository", err.Error())
		return
	}
	if current == nil || current.Mode != "hosted" {
		diagnostics.AddError("Expected hosted repository is unavailable", "Check the bound authority and tenant. Retained state requires deliberate reconciliation.")
		return
	}
	saved.Authority = types.StringValue(remote.Authority())
	saved.StateScope = types.StringValue(r.stateScope)
	saved.observe(current)
	diagnostics.Append(save()...)
}

func (r *hostedRepository) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.immutable(&resp.Diagnostics)
}

func (r *hostedRepository) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.protected(&resp.Diagnostics)
}
