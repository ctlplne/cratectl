# Preview hosted Go requirement selection

This preview is qualified at source `44bc606`: all 26 selected native jobs and
the actual read-only [verifier](https://github.com/ctlplne/cratectl/actions/runs/42416227577)
pass. Both Linux hosts exercise real PostgreSQL/current policy and the actual
TLS CLI comparison. See the [scoped checkpoint](../evidence/2026-11-07/github-44bc606-checkpoint.json).
The newer [durable requirement export](go-requirement-exports.md) remains a
separate implemented but unverified source change.

Use a tenant administrator with current read access to the chosen hosted Go
repository. Supply a single project's complete `go.mod` as a JSON string in a
private regular request file:

```json
{
  "repository": "go-hosted",
  "expected_source_revision": 0,
  "main_go_mod": "module example.invalid/project\n\ngo 1.27.0\nrequire example.invalid/library v1.2.3\n",
  "lifetime_seconds": 900,
  "max_artifact_bytes": 1073741824
}
```

Use the repository's current exact source revision. Store the request with owner
permissions because module paths and project comments can be private. The existing
management CLI supports this API through its bounded body-file interface:

```sh
umask 077
cratectl --config /private/path/client.json \
  --method POST --path /api/v1/go/export-sets/requirements/preview \
  --body-file /private/path/requirements-request.json \
  --timeout 2m --response-limit 16777216 --raw-response \
  > /private/path/requirements-preview.json
```

The response contains a proposed `selection`, its unsigned common `manifest`,
the original main-file digest, examined source identities and required Go version.
Every loaded `.mod` is checked against its original stored size and digest.
After those file reads, all examined inputs and selected roots share one final
current source/policy observation. A missing, changed, denied or over-budget
member refuses the whole response. A lower unselected version can still influence
selection; its original source policy and identity are rechecked too.

Inspect the logical/source coordinates when replacements are present and compare
`minimum_go_version` with the intended client's installed toolchain. The server
records the main toolchain suggestion without downloading or executing it.
Modern Go pruning can select modules whose `.mod` files are outside this metadata
traversal. All final selected roots still require current source eligibility.

The preview creates no export session or pins. Its proposed selection can be
reviewed for a later explicit [common set](go-export-sets.md), whose creation checks
the selected bytes and permissions again. Package/platform closure, immutable
graph attribution, authority and current destination admission remain unverified;
the response and existing export receipts keep those grants false. A complete
automatic export must retain every resolution input and recheck it during creation.

This first surface uses one hosted repository. Proxy/group routing, private-source
authority, workspaces, automatically resolving excluded direct roots and explicit
immutable local replacements remain required work. Local filesystem replacements
are refused. Dependencies' own replace/exclude directives do not override the
project's main directives.

An exclusion removes that exact dependency edge from this metadata build list.
It does not search for a replacement version or prove that every imported package
is available. A separately required lower version can remain selected after a
higher transitive version is excluded. Review package and platform closure before
treating this list as a complete project export. The
[native comparison plan](adr/0073-native-go-replacement-and-exclusion-differentials.md)
tracks exact replacement identities and these exclusion cases separately.

Budgets: 2 MiB encoded request, 1 MiB original main or dependency go.mod, 256
selected modules, 1,024 examined versions, 16,384 requirement edges, 32 MiB combined
metadata and 16 MiB encoded response. Reads are serial with a two-minute request
budget; the final database observation is bounded to 30 seconds. Preview never
executes package code. Full [export qualification](qualification/go-export-plan.json)
and all GOAL4.1 scope remain open.
