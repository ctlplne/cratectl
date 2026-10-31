# Retire old OCI manifests with a reviewed policy

A retention policy controls which live canonical manifests in one OCI repository
may be retired. Retirement creates the same retained tombstone as native OCI
deletion. It keeps the bytes and history, preserves security decisions and can be
reversed through the existing verified [restore workflow](oci-lifecycle.md).
It reports zero reclaimed bytes. Physical garbage collection remains separate.

Policies require a tenant administrator and apply to hosted or proxy OCI
repositories. Group endpoints do not own these references. Selection uses:

- **Minimum age:** seconds since the manifest reference was first created. This
  is not time since its last download or tag update. The minimum is 60 seconds.
- **Newest manifests to keep:** the number of newest live canonical manifests
  retained per image name. Ties use the canonical path. Zero disables this rule.
- **Protect tagged manifests:** keep every manifest with a current live tag.
  Disabling protection allows retiring the reviewed tagged targets; their native
  aliases become unavailable until a permitted restore or tag replacement.
- **Enabled:** allow new runs and execution. Disabling or replacing a policy
  stops further effects from jobs admitted under its previous revision.

An active hold or strong incoming manifest reference always prevents retirement.
Unvalidated legacy manifest metadata requires supported intake repair first.
Referenced layers are retained; policies currently select manifests only.

The management CLI uses the common API. Save a complete policy in a private file:

```json
{
  "expected_revision": 0,
  "min_age_seconds": 2592000,
  "keep_last": 5,
  "protect_tagged": true,
  "enabled": true,
  "reason": "Keep current releases and at least five versions per image",
  "dry_run": true
}
```

```sh
cratectl --config /private/client.json --method PUT \
  --path /api/v1/repositories/containers/retention-policies/monthly \
  --body-file /private/policy.json --idempotency-key retention-policy-preview
```

Preview does not save a configuration. Remove `dry_run` or set it to false and
apply with an idempotency key. Revision zero creates the policy; replacement
requires its exact current revision from GET on the same path. Configuration
history is immutable and available at `/{name}/history?after=0&limit=50`.

Preview a run by POSTing to that policy's `/runs` endpoint:

```json
{
  "expected_revision": 1,
  "reason": "Review this month's retained manifests",
  "dry_run": true
}
```

Read the returned items, tags, incoming references and eligibility. To apply,
reuse that reason and revision, include the exact returned `evaluated_at` and
`preview_digest`, and remove `dry_run` or set it to false. Apply within five
minutes using a new idempotency key. The server recomputes the complete plan
under the tenant mutation lock. `retention_changed` means a new preview is needed;
no partial plan was admitted. An identical successful request replay returns the
original job without executing another run, even after its preview window ends.

The complete live manifest set is bounded by the operator's native-version
budget, at most 10,000 targets and 8 MiB of retained target metadata. Oversized
plans fail with `retention_budget`; they are not silently truncated. Large-repo
pagination, additional selection rules and production-scale cost remain work.

Admission returns a maintenance job. The worker must be running. Inspect:

- Policy run history: `/{name}/runs?after=0&limit=50`; continue from the sequence
  prefix of the last returned job ID while `more` is true.
- Run and authoritative counts: `/api/v1/maintenance/retention-runs/{job}`.
- Approved targets and committed outcomes: that run's `/items?after=0&limit=50`;
  continue from the last target ordinal while `more` is true.
- Cancellation and retry: the existing `/api/v1/jobs/{job}/cancel` and `/retry`
  endpoints. Prior outcomes and tombstones remain retained.

Each target transaction rechecks the original administrator credential, current
worker lease, repository/source and policy revision, lifecycle state, age/newest
selection, tags, holds and strong parents. It can skip more targets than the
preview; it never expands the approved set. A changed tag set also prevents
retirement when tagged targets were allowed, so an older approval cannot hide a
new tag binding. Already processed targets never repeat on job retry.

Expired or revoked requester authorization and a changed policy/source stop
further effects. Inspect any earlier committed targets and create a new approved
run with a current administrator credential. Retrying an old job does not replace
its authority. Cancellation stops remaining work after the worker confirms it;
it does not undo prior retirement. Recover a specific retired manifest through
the verified lifecycle restore workflow; current unrelated tags are preserved.

Schema 7 preserves receipts 1–6 and requires controlled maintenance with earlier
registry/worker processes stopped. Earlier runtimes reject it. The owned primary
remains on schema 6 during development. Backend PostgreSQL/HTTP preflights are
in progress; clean-candidate artifacts, a dedicated stock-client retention replay
and console workflow remain pending. Other formats, scheduled runs, last-access
rules, legal-hold administration, physical GC, providers/platforms, scale and
production backup/restore remain committed requirements.
