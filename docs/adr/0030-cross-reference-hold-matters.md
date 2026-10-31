# 0030: cross-reference matters and reviewed bulk preservation

Status: named canonical OCI workflows qualified on clean isolated production/race
builds; broader scope remains required. See `evidence/2026-10-31/matter-full-checkpoint.json`.
Primary10 maintenance requires explicit owner authority and has not run.

An independent per-reference case cannot describe one investigation spanning
repositories. A tenant-wide matter records its purpose and a versioned metadata
record; immutable reference identities become separately revised memberships.
The original hold slot, per-reference cases and other matters remain independent.
The common lifecycle reader enforces their union for native deletion, restore and
retention. Membership changes advance the common lifecycle revision as a fence.

Bulk placement and release operate on a complete, bounded, explicitly reviewed
target list. Preview resolves canonical references and current membership
revisions. Admission compares the exact digest under the tenant write lock and
stores the immutable manifest, requester identity and deadline. No truncated
preview authorizes a larger operation. New members outside that manifest remain
protected when a release completes.

Placement admits a maintenance job directly. A matter release first creates a
proposal; a different current administrator must approve its exact digest and
revision before a maintenance job is admitted. Both requester and approver must
remain authorized at execution. Credential rotation or revocation cannot silently
substitute a new authority for an immutable approval. Cancelled or stale proposals
retain their receipts. Recovery uses a fresh preview/proposal for remaining work.

Workers process one immutable target per fenced transaction. A membership change,
its lifecycle revision, immutable observation/event and outbox work commit
together. Earlier committed outcomes survive cancellation, retries and process
failure; retries never repeat a completed target. Mutable job progress is never
execution authority. Queue failure rolls back the whole affected transaction.

Inventory, proposals, outcomes and history use bounded pages and credential-bound
encrypted cursors. API, management CLI and console use the same store and current
authorization. The operator sees pending approval, admitted, partial, cancelled,
failed and complete states with the actual affected references and next action.

Migration 11 appends forced-RLS matter, membership, operation, target and outcome
tables. Receipts 1–10 remain frozen. Development uses isolated schema11 databases;
the qualified primary and active binaries remain schema10 until matching runtime
qualification and controlled maintenance pass. Never restore older binaries onto
a newer primary.

This work establishes canonical OCI matter workflows. Mutable coordinates and
retirement adapters for every other format, broader legal policy, physical GC,
release/replica/restore protections, production recovery and all later committed
scope remain required. No legal-compliance or broad readiness verdict follows.

The maintained native journey is `scripts/conformance_hold_matters.py`. It uses
stock ORAS and the management CLI against a fresh isolated database, kills leased
workers between targets, waits for actual lease expiry, and tests partial
cancellation/retry plus requester/approver revocation during a paused effect.
An explicit ordinal-two SQL trigger supplies the timing fault. The shared owned
timing helper records and closes its exact backend; it never edits leases or
manufactures memberships/outcomes. Clean production/race qualification must run
this journey in addition to the store, browser and prior native regressions.
