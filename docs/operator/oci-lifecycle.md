# Retire and recover retained OCI content

Native hosted repositories accept OCI `DELETE` for SHA-256 manifests, blobs and
individual tag aliases. Stock ORAS can retire a manifest with
`oras manifest delete --force REGISTRY/REPOSITORY/IMAGE@sha256:DIGEST`, using its
normal private registry configuration and CA trust. A successful response is 202.
This retires a reference; it does not erase its stored bytes or reclaim space.
Native writes to proxies and groups remain read-only.

A deleted canonical path has an authoritative tombstone. GET, HEAD, conditional
requests, ranges, native discovery, proxy refresh and group selection honor it.
Re-publishing the same bytes does not restore that canonical reference. A deleted
manifest hides aliases still pointing to it; restore preserves later tag changes.
Deleting a tag changes only that binding. A strong incoming manifest reference
blocks deletion of its child. Subject relationships are weak associations, but a
known deleted subject makes its dependent attachments unavailable.

The console offers **Lifecycle** beside each repository for administrators and
beside canonical OCI package references for writers. Choose an action and reason,
then **Preview impact**. Inspect active transfers, referencing groups, parent
manifests, aliases and holds before applying. The action uses that exact revision;
a concurrent change requires a new preview. An unconfirmed response retains its
original request and idempotency key for retry. The existing exact-byte security
decision remains visible separately from deletion and holds.

The management CLI supports the same workflow. Read repository state:

```sh
cratectl --config /private/path/client.json \
  --path /api/v1/repositories/containers/state
```

Save a JSON body in a file, initially using `"dry_run":true`:

```json
{"action":"suspend","expected_revision":0,"reason":"Planned source maintenance","dry_run":true}
```

```sh
cratectl --config /private/path/client.json --method PUT \
  --path /api/v1/repositories/containers/state \
  --body-file /private/path/lifecycle.json --idempotency-key maintenance-20261029
```

After reviewing the preview, set `dry_run` to false and use a fresh idempotency
key. An untouched record has revision 0. `suspend` and `remove` fence bounded
active uploads/retrievals atomically with the state, journal, job intent and saved
response. `resume` admits fresh operations after suspension. `restore` is required
after removal. Old writer generations cannot commit after resume or restore.
Retained committed cache data remains governed by its current source and policy.
A group fails while a required source is inactive; it cannot silently substitute
a lower source. The preview names groups that use the repository.

For an artifact, GET
`/api/v1/repositories/containers/artifacts/lifecycle?path=IMAGE%2Fmanifests%2Fsha256%3AHEX`.
PUT the same endpoint with a JSON body containing `path`, the 64-character `digest`
without `sha256:`, `action`, `expected_revision`, `reason` and `dry_run`.
Actions are `delete`, `restore`, `hold` and `release_hold`. Holds require an
administrator; optionally set `hold_until` to a future RFC3339 timestamp. Without
an expiry the hold persists until an administrator releases it. An active hold
blocks deletion, restoration and native tag deletion. A preview reports blockers
without applying the action. Reference and transfer counts are bounded by the
configured native version budget and an 8 MiB aggregate text budget; oversized
operations fail without partial work.

Restore hashes retained objects, checks their exact sizes, reparses manifests and
revalidates the complete retained graph. Deleted children must be restored first.
Missing/corrupt bytes or changed graph identities reject the operation. Use
[exact-byte repair](byte-repair.md) with an independently retained matching copy
before retrying restore. Older unvalidated manifests require native intake repair
before deletion; byte repair preserves their existing metadata. Restore
preserves denial and quarantine; it never labels unassessed bytes security-clean.
A stored idempotency response can confirm an earlier successful restore even if
storage subsequently becomes unavailable, while current write grants still apply.

Schema 3 adds forced-RLS lifecycle tables; schema 4 adds source revisions and
immutable configuration history; schema 5 admits repair-capable runtimes. Schema
6 adds recurring integrity, schema 7 retained retirement and schema 8 explicitly
authorized automatic retirement. Schema 9 indexes hold inventory and original
journal history. Stop registry and workers, inspect
`cratectld migrate --plan` with owner configuration, apply the planned steps, then
start the matching new binaries. Receipts 1–8 keep their original checksums.
The owned primary is schema 9; older runtimes reject it. This is controlled maintenance; rolling
compatibility, whole-transfer draining, backup/restore and downgrade recovery
remain unqualified.

The native campaign is `scripts/conformance_lifecycle.py --require-clean-build`;
it retains the old 405 baseline and tests a real version-2 upgrade, stock ORAS,
restart, holds, strong references, verified restore, policy and proxy lifecycle.
Add `--baseline-version 3` to test a real schema-3 cached OCI graph upgrade.
Use `--baseline-version 4` for source configuration, `5` for byte repair, `6` for
recurring integrity, `7` for retained retirement and `8` for automatic retirement
with an actual pre-upgrade hold receipt. Every baseline is an actual
retained qualified binary, not a schema-version label on the current executable.
Use the project-owned PostgreSQL environment and clean matching binaries. See
[source configuration](source-configuration.md) for versioned source changes.
See [reference holds](holds.md) for tenant inventory, original history and
administrator recovery in retained repositories. The
[current checkpoint](../../evidence/2026-10-31/hold-checkpoint.json) identifies
the exact production/race artifacts and scope.
Full lifecycle parity, broader source/locator/grant races,
other retention rules/formats, legal-hold administration, physical erasure/GC,
large graphs, other clients/platforms and
production recovery remain committed work.
