# Find, inspect and recover reference holds

A hold protects one exact canonical OCI manifest or blob reference from deletion
and restore. Downloads keep their existing repository and content-policy checks.
Release preserves the reference, bytes and earlier journal receipts.

In **Storage → Reference holds**, choose active, expired, released or all records.
Filter by an exact repository name or search repository/path/digest and reasons.
Search is literal, with Unicode case folding; punctuation is not a regular
expression. This view requires a current tenant administrator credential.

**Inspect hold history** shows actual hold/release receipts, including records
created by earlier supported binaries. An expiry changes today's observation;
it does not rewrite the original receipt or invent a release event. The event
hash identifies its full audit record. A filtered list is not the complete audit
chain and cannot independently verify that entire chain.

**Manage hold** reads current state again before preview. Active and expired rows
start with release selected; released rows start with placement selected. Supply
a reason, preview and apply the exact revision. A concurrent change rejects stale
input. An uncertain response retains the original request and idempotency key for
retry. Current administrator authority still applies to replay.

An administrator can inspect, place or release a hold while its repository is
suspended or retained in removed state. These actions grant no serving authority.
Resume or restore the repository separately when appropriate; its native serving
fence remains in force until then. Revoking the original administrator credential
does not remove an existing hold. A different current administrator can recover
the same record using its current revision.

The current per-reference API has one hold slot. A new placement replaces that
slot's reason/expiry under the exact revision. Independent case-scoped holds,
case-specific release, bulk/legal workflows, other formats, physical GC and full
production recovery remain required work. This feature is not a legal-compliance
verdict. An omitted expiry means explicit administrator release is required.

## API and CLI

Use a private client configuration that contains the server trust and credential
file references. Credential values are never query parameters or command arguments.

```sh
cratectl --config /srv/cratectl/operator/client.json \
  --path '/api/v1/holds?state=all&limit=100'
```

The result contains `items`, `observed_at`, `next`, `previous`, `limit` and a live
page scope. Copy a returned continuation unchanged into the `cursor` query, with
the same credential and filters. Each page supports 1–100 rows, a configured byte
budget and the common database execution limit. `q` is at most 256 UTF-8 bytes.
Unknown/repeated parameters and differently scoped cursors fail explicitly.
An oversized first record fails without returning a partial record. A byte budget
may shorten a page; follow the returned continuation rather than assuming a fixed
total count. Pages are observations, not a multi-page snapshot. Expiry and other
administrators' actions can alter traversal; restart to see earlier insertions.

Read original receipts with the management CLI using:

```sh
cratectl --config /srv/cratectl/operator/client.json \
  --path '/api/v1/repositories/example/artifacts/lifecycle/history?path=app%2Fmanifests%2Fsha256%3AEXACT_DIGEST&limit=100'
```

Substitute the actual canonical reference and URL-encode it once. History has its
own encrypted `next`/`previous` continuations. They cannot be exchanged with
inventory cursors or another reference. Exact large integer values remain
available through the CLI/API when the browser cannot represent them safely.

Placement and release continue to use `PUT /api/v1/repositories/{repository}/artifacts/lifecycle`
with `path`, exact `digest`, `action`, explicit `expected_revision`, reason and an
idempotency key. `hold_until` is optional for placement and must be in the future.
The existing lifecycle API performs preview with `dry_run: true`. Inspect the
current revision before applying; do not infer it from an old history page.

## Upgrade and qualification limits

Migration 9 adds indexes over current state and existing immutable journal data.
It preserves receipts 1–8 and does not synthesize or rewrite tenant history.
Stop registry/workers, inspect the owner migration plan, apply the planned step
and start matching binaries. Index construction reads the existing tables and
needs a controlled maintenance window. Older runtimes reject schema 9. Rolling
compatibility, downgrade and production backup/recovery remain unqualified.

Named clean production/race evidence covers PostgreSQL/HTTP, actual-time expiry,
concurrent stale revision rejection, queue rollback, tenant/cursor/credential
boundaries, actual old schema-8 hold receipts, CLI/ORAS and eleven Chromium
workflows/81 automated A/AA states. The owned primary is schema 9 after controlled
maintenance; every earlier receipt is unchanged. Full product, format, legal
retention, provider/platform, accessibility, scale and production recovery remain
required. [The checkpoint](../../evidence/2026-10-31/hold-checkpoint.json) identifies
the exact source, artifacts, observations and limits.
