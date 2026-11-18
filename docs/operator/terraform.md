# Use the local cratectl provider

Build the candidate with `make build-provider`. Use Terraform or OpenTofu
with a filesystem mirror containing the provider binary. The provider runs
on the operator's workstation and communicates with the normal, tenant-scoped
cratectl management API. It needs an absolute path to the private
administrator client configuration from the expected tenant.

The local provider address is `ctlplne.dev/ctlplne/cratectl` and the candidate
version is `0.1.0`. For a Linux x64 host, place the binary in the unpacked
mirror using this layout. Use `linux_arm64` on Linux ARM64 or `darwin_arm64`
on macOS ARM64 with a corresponding build.

```text
MIRROR/ctlplne.dev/ctlplne/cratectl/0.1.0/linux_amd64/terraform-provider-cratectl_v0.1.0
```

Point `TF_CLI_CONFIG_FILE` to a private CLI configuration. Use a mirror you
control and verify the candidate binary digest before copying it.

```hcl
disable_checkpoint = true
provider_installation {
  filesystem_mirror {
    path    = "/absolute/path/to/mirror"
    include = ["ctlplne.dev/ctlplne/cratectl"]
  }
}
```

```hcl
terraform {
  required_providers {
    cratectl = {
      source  = "ctlplne.dev/ctlplne/cratectl"
      version = "= 0.1.0"
    }
  }
}

provider "cratectl" {
  client_config = "/private/installation/client.json"
  state_scope   = "first-team-packages"
}

resource "cratectl_hosted_repository" "packages" {
  authority      = "https://localhost:38443"
  tenant         = "first-team"
  name           = "packages"
  format         = "npm"
  access         = "restricted"
  require_review = true
}
```

Use `init`, then `plan -out=create.tfplan` to review a saved creation plan.
Use a different stable `state_scope` for each independent state. The plan
binds the registry authority, tenant and scope for idempotent creation. Apply
the saved plan using `apply create.tfplan`. A competing repository requires
explicit import. The provider keeps bearer credentials in the private client
configuration and sends them only to the configured registry. Keep state and
plan files private as they identify tenant resources.

Import an existing hosted repository using its tenant and name.

```sh
terraform import cratectl_hosted_repository.packages first-team/packages
terraform plan -refresh-only
```

The same commands work with `tofu` in place of `terraform`. Refresh reports
retained lifecycle state and revision, including suspension or removal.
Updates to the declared repository fields require operator review and explicit
reconciliation. Repository retirement is handled through cratectl's
revision-checked lifecycle API. If management of an existing repository moves
out of Terraform/OpenTofu, confirm the bound identity before detaching it
from state.

The candidate provider has one hosted repository resource. Other
cratectl resources, provider distribution and broader platform
qualification remain open.
