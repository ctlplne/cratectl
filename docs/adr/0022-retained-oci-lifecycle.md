# Retained OCI content and repository lifecycle

Add a reversible, tenant-scoped lifecycle separate from digest security decisions.
Keep immutable artifact references and CAS bytes. A deleted canonical path has an
authoritative tombstone; reads, discovery, proxy intake, retained locator lookup
and new publication must honor it. A local delete must not become an upstream
miss or group fallback. Re-publication does not implicitly restore a tombstone.

Native digest DELETE returns 202 after the tombstone/event commit. Tag deletion
changes only that tag binding. Management provides bounded preview, expected
revision, idempotency, explicit restore and administrator holds. Strong incoming
manifest references block child deletion. Tags and weak subjects are reported;
tag aliases disappear with their deleted manifest and current unrelated retargets
are preserved. A deleted subject blocks dependent reads rather than being treated
as a never-observed weak subject. No physical reclamation or freed-byte claim is
made. Retention policy, legal-hold administration and future GC must preserve
these records and bytes until their full requirements are implemented.

Repository suspension/removal is also retained state, with explicit resume or
restore. Authorize against the base repository record before reporting inactive
state; lifecycle administration can inspect that record while ordinary serving
fails closed. Group/source authorization failures never authorize fallback.
Bounded active retrieval/upload fencing commits with state, event and outbox.
Resuming cannot revive a previously fenced writer. Retained committed cache data
and exact policy/grants remain, while source configuration changes are a separate
versioned operation still to be completed.

Introduce migration 3 with forced-RLS artifact/repository lifecycle tables. Freeze
steps 1 and 2 byte-for-byte. The state function validates the table set belonging
to its applied version, so a version-2 database can be inspected/upgraded by the
new migrator without weakening current-version safety. Old runtime binaries fail
schema compatibility after upgrade. Use controlled maintenance; rolling/version
compatibility is not inferred from an additive schema change.

Restoration verifies retained bytes and the current complete manifest graph,
then compares revision/identities again before clearing deletion. It preserves
manual denial and quarantine and never equates restored with security-approved.
Missing/corrupt bytes, deleted children, changed bindings, holds, authorization,
queue failures and stale operation revisions retain explicit failure/retry state.

Qualify actual ORAS deletion/pull/discovery/restart/restore and proxy/group local
tombstones, source suspension/removal/restore, in-flight fences, shared bytes,
policy/tenant/grant boundaries, holds, missing/corrupt bytes and transaction faults
on real PostgreSQL. Preserve failed baselines and exact committed artifact IDs.
Complete lifecycle, source-configuration/locator races, retention/GC, other clients,
platforms, scale and production recovery remain required.

Primary protocol: [OCI Distribution 1.1.1 content management](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#content-management),
observed 2026-10-29. Soft deletion/restore and holds are explicit cratectl product
semantics; they do not imply that bytes were physically erased.
