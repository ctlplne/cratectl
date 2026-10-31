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
Canonical OCI cross-reference matters and reviewed bulk changes are in development
below. Other formats, broader legal policy, physical GC and full production recovery remain required. This feature is not a
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

## Cross-reference matters and reviewed bulk work

In **Storage → Reference holds → Cross-reference hold matters**, create an open
matter with its purpose and reason. Inspect the matter and choose **Preview
membership change**. Supply one repository and canonical digest path per line,
separated by a space. For example, a manifest reference is
`example app/manifests/sha256:EXACT_DIGEST`. The server resolves each immutable
reference; it rejects duplicates and a complete list that exceeds its configured
target or metadata budget. A matter can span repositories within one tenant.

Review all targets, reason and optional future expiry. Admission must echo the
complete preview unchanged within fifteen minutes. A concurrent metadata,
membership or lifecycle change invalidates admission. Placement queues a durable
operation. Release creates a proposal with no release job. In **Operations and
approvals**, a different current administrator inspects and acknowledges every
target page, supplies a review reason and approves the exact proposal revision
and digest. Another token belonging to the requester cannot approve it.

Every worker step rechecks the original requester and, for release, the original
approver. Editing matter metadata, expired intent or changed authority stops
further effects. A changed membership is recorded as `changed` and remains
protected. Members added after the reviewed manifest remain outside its release.
Releasing a member preserves other matters, independent cases and the original
hold slot. Repository suspension/removal continues to fence serving.

Inspect actual job state and per-target outcomes, rather than treating the
operation's `approved` review state as completion. `Processed` includes skips;
`changed` and `already_released` are observations rather than new releases.
Cancellation preserves committed effects and stops remaining work when observed.
Retry resumes the same immutable intent and never repeats observed targets.
Retry does not transfer authority or extend its deadline. After revocation or
expiry, use a current administrator's fresh preview/proposal for the remaining
targets and obtain a new independent approval. A current administrator may cancel
a stranded pending proposal. Closing a matter requires every member explicitly
released, including expired members, and no pending proposal or live job.

The CLI uses the same management API and exact JSON bytes. Keep request files and
idempotency keys for uncertain responses. For example:

```sh
cratectl --config /srv/cratectl/operator/client.json --method PUT \
  --path /api/v1/hold-matters/investigation \
  --body-file /srv/cratectl/operator/matter.json \
  --idempotency-key create-investigation

cratectl --config /srv/cratectl/operator/client.json --method POST \
  --path /api/v1/hold-matters/investigation/operations/preview \
  --body-file /srv/cratectl/operator/targets.json \
  > /srv/cratectl/operator/reviewed-plan.json

cratectl --config /srv/cratectl/operator/client.json --method POST \
  --path /api/v1/hold-matters/investigation/operations \
  --body-file /srv/cratectl/operator/reviewed-plan.json \
  --idempotency-key investigation-operation
```

`matter.json` contains explicit `expected_revision: 0`, `state: "open"`, `title`
and `reason`. `targets.json` contains `action: "hold"` or `"release_hold"`,
`reason`, a complete `targets` array of `{ "repository": "example", "path":
"app/manifests/sha256:EXACT_DIGEST" }`, and an optional future `hold_until` for
placement only. Omit expiry for indefinite preservation and release. The preview
does not require an idempotency key; the CLI may supply one without changing its
read-only semantics. Increase `--response-limit` explicitly for a complete large
preview; never submit truncated output.

Read `/api/v1/hold-matters/investigation/operations/SEQUENCE/items` with bounded
`limit` and returned `cursor` to inspect every immutable target. Submit `POST`
to the operation's `/approve` or pending `/cancel` endpoint with explicit
`expected_revision`, `preview_digest` and review `reason`, plus an idempotency
key. After admission, ordinary `/api/v1/jobs/JOB_ID/cancel` and `/retry` apply.
Matter inventory supports literal `q`; members support `state`, exact
`repository` and literal `q`. Inventory, members, operations, items and history
support `limit` 1–100 and opaque cursors bound to their endpoint, filters and
current credential. These are live pages, not a snapshot. Filtered history
preserves original receipts and does not independently prove the complete chain.

Migration11 adds five forced-RLS tables and preserves receipts1–10. Clean source
`d7d9bdbf2a3a255121c11572d8032bfc8d810607` passes the named isolated production/race
campaign: 444PostgreSQL test passes, all13browser workflows/100automated
accessibility states perbuild, actual old2–10 native upgrades and31native matter
recovery assertions perbuild. See [the scoped checkpoint](../../evidence/2026-10-31/matter-full-checkpoint.json).
This does not qualify other formats, broader legal policy or production recovery.

The project primary and active binaries remain schema10. Automatic approval
review rejected a durable primary10to11 migration without explicit owner authority;
no primary migration ran. The [maintenance proposal](../../evidence/2026-10-31/matter-full-primary-maintenance-proposal.json)
records the completed checks and remaining controlled steps. Use isolated schema11
candidate deployments while primary maintenance is pending. Full release and
legal-compliance qualification remain open.

The native fault journey runs with `python3 scripts/conformance_hold_matters.py
--require-clean-build` using the configured owned test PostgreSQL environment.
It creates a separate database and stops its registry/workers afterward, retaining
private data/logs and public scoped evidence. `--binary-directory` selects an owned
candidate directory inside the workspace without replacing active binaries.
The journey declares its SQL timing faults and verifies real process death,
elapsed lease expiry, partial cancellation/retry and both authorities' revocation
before fresh independent approval. It does not qualify production recovery.

All native qualification drivers also honor `CRATECTL_QUALIFICATION_BIN_DIR`.
Build a separate candidate with `make build BINDIR=.cache/candidate-production`,
then set that variable to the candidate directory when running native checks.
The selectors reject paths or symlinks outside this workspace. This keeps the
active `bin/` bytes intact while another schema is tested in isolated databases.
Evidence records the selected artifact paths and actual embedded source identity.

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
