# ADR 0027: explicitly authorized scheduled retirement

Status: backend, console and dedicated stock-client/cadence/recovery development
preflights pass; exact clean qualification pending.

One-time retention approval continues to cover its exact captured target set.
A separate schedule authorizes future bounded captures under one exact OCI
retention-policy revision and repository source revision. Enabling requires an
explicit `authorize_future_retirements` acknowledgment, exact schedule/policy/
source revisions, interval, maximum target count and reason. Configuration
preview has no effects. Each replacement records immutable configuration history
and binds the current administrator credential; credentials stay private.

One schedule belongs to one policy. A dedicated bounded worker loop visits
tenant identities fairly and admits at most one due schedule per transaction.
Database time defines cadence. Missed intervals coalesce into one current capture,
with an immutable due-slot receipt and count; there is no catch-up burst. The
complete manifest set must fit the approved target count, the server ceiling and
the existing metadata bounds. An oversized capture defers without partial work.
An active manual or scheduled run of the same policy defers automatic admission.

Admission uses the common retained-retirement path: immutable approval and target
rows, maintenance job, journal/outbox and due-slot receipt commit in one tenant-
serialized transaction. Capacity, repository availability and snapshot budgets
produce visible deferral states without advancing the due slot. Revoked/expired
requester authority, changed policy or changed source blocks future admission
until an administrator explicitly authorizes a new schedule revision.

Every scheduled target checks the immutable schedule receipt as well as existing
requester, worker lease, policy, source, hold, tag, reference and lifecycle fences.
Changing or pausing a schedule stops unprocessed targets from its earlier runs;
earlier committed outcomes remain retained. Manual runs retain their existing
approval semantics. Retrying an old job cannot replace its original authority.

Schema 8 adds forced-RLS current schedules and append-only configuration/due-slot
receipts, preserving migrations 1–7. Runtime roles cannot rewrite or delete the
immutable records. Controlled maintenance is required; older runtimes reject the
new schema. No physical bytes are erased or reported as reclaimed.

Other retention rules/formats, calendar schedules, legal-hold administration,
physical GC, release/replica/restore protections, provider/platform/fault/scale
and production recovery remain required. This record does not qualify them.
