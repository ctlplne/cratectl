# Durable hosted Go export snapshots

Status: named source-15 native cases verified; full export scope incomplete.
Exact `15a49d3` passes 93 named Go PostgreSQL functions normally/under race and
312 stock checks on both Linux architectures, plus a separate 16-stage x86
producer/ARM consumer. See the [Go checkpoint](../../evidence/2026-11-07/go-module-15a49d3-native-checkpoint.json)
and [portable checkpoint](../../evidence/2026-11-07/go-export-portability-15a49d3-checkpoint.json).
Historical source-15 upgrades and main Chromium proof remain source-specific;
the complete 15a49d3 campaign is not accepted because ARM upgrade bootstrap fails
before qualification. [ADR0053](0053-indexed-export-expiry.md) adds source-16
indexed expiry and old schema-15 export preservation; its new native campaign
is in progress. This decision below describes the original schema-15 profile,
one hosted version rather than complete dependency/authority/permissions export.

## Commit immutable identity after storage is durable

A preview reads one repeatable PostgreSQL snapshot under forced tenant RLS. It
captures the exact ZIP/mod/info paths, digests, sizes, original metadata and
timestamps, effective decisions and decision versions, lifecycle context,
repository access/review settings, source epoch and observed journal head. The
preview is unsigned and explicitly has not verified physical bytes.

Creation reads back all three existing CAS objects with their declared hashes,
checks the inert Go archive/mod/info as one bundle, and stages/syncs a bounded
canonical manifest through the common blob store. Storage I/O holds no long SQL
transaction. Under the existing tenant mutation fence, re-read and compare the
complete original byte/policy snapshot. Unrelated journal appends do not replace
the captured observation or force a different package snapshot. A byte, source,
policy-version or lifecycle change rejects the staged plan. A plan older than
five minutes is rejected. Retain unreferenced staged bytes after uncertain or
failed admission; this request never deletes them.

The session, three immutable items, original creation event, idempotency response
and event-projection job commit together. Queue saturation rolls everything back.
Replay checks current administrative authority and returns the original response;
read current status before using its generation. Export IDs are scoped resource
identifiers, not bearer credentials. All operations require current tenant admin
access because this profile includes retained policy and journal context.

## Bound serving and retain references until a durable terminal transition

Schema15 appends `artifact_exports` and `artifact_export_items` with forced RLS,
composite tenant references and narrow runtime grants. Runtime cannot rewrite
manifest/item identity. The first fourteen migrations remain byte-for-byte
frozen. Inventory gains an additive export-reference count: historical manifests
remain referenced, and open/acknowledged sessions protect original package bytes.

Initial serving lifetime is60–3600seconds. Renew within the original24-hour
maximum window. Each accepted renewal, acknowledgment, cancellation or expiry
increments generation. Each object request verifies current credential, active
source epoch, all-three-representation authorization and policy, original item
identities, generation and deadline. Verify stored bytes before headers and
recheck afterward. Long bodies recheck the SQL fence every second; an expired,
revoked, denied or superseded request is interrupted. A request has a maximum
90-second deadline and supports one bounded HTTP range. Conditional and HEAD
responses authorize first. A client must verify the complete exact digest before
accepting a resumed copy. Already sent bytes cannot be revoked.

Wall-clock expiry alone is not deletion intent. A due session is
`expired_unreconciled`, still retaining payload pins, until the expiry event,
state, idempotency response and job intent commit together. Queue failure keeps
pins and rejects admission. Reading a due session attempts reconciliation;
operators may also reconcile or cancel explicitly. A terminal expired/cancelled
state cannot be renewed by moving the expiry timestamp forward. Retained-session
capacity includes unreconciled expiry and is operator-configured with
`--export-session-limit`; it is a resource bound, not an edition limit.

Acknowledgment is the caller's statement of collection. `delivery_verified`
remains false. Acknowledged sessions keep pins through their serving window;
terminal cancellation/expiry releases package pins while preserving manifest and
journal history. No physical GC operation or safe-to-delete verdict is added.
Future GC must consider every other required live/hold/transfer/release/replica/
restore reference under the same mutation fence. Background expiry janitor,
provider/platform/clock-fault/large-load and complete physical-GC qualification
remain required; timestamp-fault tests are explicitly distinct from real clock
or independent-host evidence.

## Independently authenticate the captured historical context

The API's adjacent manifest hash is an identity, not trust. `go-module-offline`
can accept a private canonical manifest plus an explicitly selected export ID
and original `go.export.created` event. Authenticate the complete journal through
an externally signed checkpoint and separately trusted public key, then match
original tenant/repository/module/version/source/creation sequence and exact
manifest digest/size. Only after that may its three digests select input bytes.
Copy, hash, inspect and sync the same private files used by the original hosted
publication mode. Persist the original manifest beside the resulting file proxy.
All old publication-mode controls remain.

The manifest retains historical source decisions. Current registry admission,
checksum-authority approval and dependency closure remain false. No signing key,
signer service, CA or credential lifecycle is introduced. Customer signing stays
external. Complete transitive closure, public proxy authority proof, source
permission mapping, destination current-policy/scanning import, independent-host
transfer/verification, backup/restore, other formats and every later GOAL outcome
remain committed. The strict three-host stock Go failure0126 remains independent.

## Native acceptance

New source has268full PostgreSQL functions,90named Go functions and55fuzz targets.
Keep original312stock Go/683baseline checks and all existing clients. Rebuild14
historical sources, including the qualified schema14 `809e826` binary, and run
schema2–14 controlled maintenance into15 with19reports per Linux architecture.
The new14→15 journey retains actual old Go bytes, metadata, timestamps and manual
approvals, then exercises new snapshot creation, replay, manifest readback and
live no-op maintenance. Declared SQL prefix fixtures separately verify every old
receipt/row, default inventory count and new FORCE/runtime boundaries. Rollback
injection stays in frozen backfill step14 rather than moving to the last step.

Main x86 Chromium adds one explicitly declared export response-stand-in workflow:
19workflows/151checks, with four declared UI stand-ins. Actual database, byte,
authority, expiry/fence, external signature and stock SDK proof remains separate.
Skips and unselected workflows never pass. The stopped primary11 and its selected
qualified binaries are untouched; source15 is for isolated qualification only.
