# Read registry evidence over local MCP

The standalone `cratectl-mcp` process offers scoped registry metadata to a
locally controlled MCP client. Build it with `make build-mcp`. The adapter
uses the existing management API and the current tenant, repository grants
and artifact policy that apply to other readers.

Use the appropriate scoped client credential and an absolute path to its
private configuration. Explicitly choose the registry authority and tenant.
The `--allow-metadata` flag authorizes those results to reach the local
client connected to this process. Obtain separate explicit consent before
forwarding any results beyond the deployment.

```sh
cratectl-mcp --client-config "$CLIENT" --authority https://localhost:38443 \
  --tenant first-team --allow-metadata
```

Configure the MCP client to start this command with stdio transport. The
current SDK supports MCP 2026-07-28 and negotiation with earlier supported
versions. The adapter checks the authority and current tenant credential on
every request.

The tool inventory includes the current session, repository list and
repository inspection, artifact reference list and exact artifact reference
inspection. List tools accept a bounded page size, literal search and the
original opaque cursor from the same read scope. The outputs identify the
registered authority, tenant and management endpoint. Artifact evidence
includes the exact digest and current recorded decision.

Repository configuration credentials, raw artifact bytes and arbitrary
management paths are outside this tool set. Make publication, approval,
grant, and lifecycle changes through cratectl's documented management tools.
The adapter uses local standard input and output, verified HTTPS to its
configured registry and a bounded read budget. It starts independently of
any model integration.
