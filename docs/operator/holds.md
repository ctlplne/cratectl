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

The original per-reference API retains one hold slot. A new placement replaces
that slot's reason/expiry under the exact lifecycle revision. Independent named
cases now provide additional protection for the same reference. Releasing the
original slot or any one case leaves every other active protection in force.
Bulk/legal workflows, cross-reference matters, approval workflows, other formats,
physical GC and full production recovery remain required. This feature is not a
legal-compliance verdict. An omitted expiry requires explicit administrator release.

## Independent named cases

Storage → Reference holds includes **Independent hold cases**. Choose **Place
independent hold**, enter the repository, canonical digest path and case name,
then read the current case before previewing. Each case has its own revision.
Names start with a lowercase letter and contain at most 63 lowercase letters,
digits or hyphens; `legacy` is reserved. A name identifies a case for that exact
repository/reference, rather than a tenant-wide legal matter.

The management CLI exposes the same API. For example:

```sh
cratectl --config /srv/cratectl/operator/client.json \
  --path '/api/v1/hold-cases?state=all&repository=example&limit=100'

cratectl --config /srv/cratectl/operator/client.json \
  --path '/api/v1/repositories/example/artifacts/holds/review-a?path=app%2Fmanifests%2Fsha256%3AEXACT_DIGEST'
```

A new case returns revision zero with the existing reference's exact digest.
Send `PUT` to that case endpoint with `path`, `digest`, `action: "hold"`, explicit
`expected_revision`, nonblank `reason` and optional future `hold_until`. Preview
with `dry_run: true`; apply with `dry_run: false` and a fresh idempotency key.
Use the CLI's `--body-file` and `--idempotency-key` options. Keep the exact body
and key for an uncertain response. Reading the case never bypasses current
administrator authorization.

Release uses `action: "release_hold"`, the current **case** revision, a release
reason and no expiry field. Releasing case A preserves case B and the original
slot. The returned `current.held` reports whether any active protection remains.
The original preservation reason/expiry remains in the released case, while
`reason` explains its latest change. A previously released or expired case may
be placed again using its current revision. Its original receipts remain intact.

Read `/artifacts/holds/review-a/history?path=...` for actual case events. Case
inventory supports `state`, exact `repository`, exact `path`, exact `case_id`,
literal `q`, `limit` and returned `cursor`. History supports `path`, `limit` and
`cursor`. These pages use the same current-authority, row/byte limits and encrypted
continuation rules as the original hold inventory. Editing a case preserves its
inventory position; filtering and expiry can still change later live pages.

Migration 10 adds case storage with forced tenant RLS and preserves receipts 1–9.
It does not convert old slots into cases or invent historical actions. The implementation uses isolated qualification databases. The project-owned
primary and active binaries reached schema10 after the complete recorded native
production/race campaign and scoped source/artifact checks passed.
Scoped clean schema-10 case qualification passes on both builds; see
[the case checkpoint](../../evidence/2026-10-31/hold-cases-checkpoint.json). The
[full runtime checkpoint](../../evidence/2026-10-31/case-full-checkpoint.json)
records the controlled primary9to10 maintenance and unchanged existing table
byte digests. Older runtimes reject schema10. The schema-9 evidence below retains
its original historical scope.

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
workflows/81 automated A/AA states. That historical checkpoint recorded primary9 after controlled maintenance;
every earlier receipt was unchanged. The current primary10 maintenance is
recorded above. Full product, format, legal
retention, provider/platform, accessibility, scale and production recovery remain
required. [The checkpoint](../../evidence/2026-10-31/hold-checkpoint.json) identifies
the exact source, artifacts, observations and limits.

A released original-slot row may still report `held: true` when a named case
remains active. Use the independent-case inventory with the exact repository
and path to find that protection. Releasing one slot never releases all cases.
