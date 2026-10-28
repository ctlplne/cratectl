# Package, API and evidence conventions

Module: `ctlplne.dev/cratectl`. Internal implementation under `internal/`; no
public SDK stability promise yet. Management paths start `/api/v1/`; native
protocols have independent paths and use ordinary clients. Errors have stable
machine codes and an operator action. Credentials come from private files or
environment, never command-line flags or URLs. Do not log database URLs.

Capability IDs use `FMT.<FORMAT>.<OPERATION>` or `<DOMAIN>.<JOB>`. Journey IDs use
`J.<DOMAIN>.<CASE>`. Evidence records candidate commit, tool versions, topology,
input digests, command, exit code and limitations. A result applies only to its
named journey. Broader matrix rows stay unverified until their entire contract
passes. Defects record first failure, repair commit and replay evidence.

Small profile: one macOS arm64 process and a project-owned PostgreSQL container;
not a production scale or HA qualification. Standard profile: 8 vCPU, 32 GiB,
1M versions and 100 tenants per GOAL.md. Large profile: independent nodes, 10M
versions, 1,000 tenants and 1,000 concurrent clients. Neither larger profile is
available or tested yet. Preserve the owner's performance budgets unchanged.
