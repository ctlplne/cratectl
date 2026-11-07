# Recover unattributed checksum incidents without inventing proof

Status: implemented and verified within the exact source14 selected native
campaign at `5816b2723e3e032569c6c83d9960b62375100e27`:29jobs/22safe83reports,
79Go/253fullPG normally/race onbothLinuxhosts,13historical native rebuilds and18
upgrade reports each,48fuzz/source3hosts and17x86browser workflows including two
explicit checksum UI response stand-ins. See
`evidence/2026-11-07/github-5816b27-checkpoint.json`. Declared13SQLincident fixtures
and actual historical binary maintenance remain separate. Full450capabilities,
41families and laterGOAL4.1stages remain. PublicGo proxy/fullchecksum-onstock,
independent journal anchor/export/offlinecache/install/backup/GC/conditionalrefresh
and readiness remain open; primary11 is untouched.

Source-12 prototypes retained a failed-attempt label and journal entry, without
the original authority responses. The label alone cannot authenticate a fork.
The repository may since have changed its key, source or lifecycle state; its
current configuration cannot establish the old incident's key attribution.
An empty source-13 failure history therefore cannot establish safe recovery.

The recovery contract needs two distinct facts: an immutable incident requiring
operator review, and an independently authenticated key fork. Preserve both.
Never transform the former into the latter, erase its original journal bytes,
or let administrative review clear an authenticated key block.

## Durable incident boundary

Append a new migration only after qualifying source 13. Keep all thirteen existing
migration definitions/checksums frozen. Retain an immutable tenant-scoped incident
for each historical checksum-fork journal label lacking a matching retained
failure/key-block witness. Bind its original event sequence and hash with a foreign
key to the retained event; preserve original payload bytes rather than rewriting
them as a new proof. Historical source/key attribution may be unknown and must be
represented as unknown. A mismatched or orphaned evidence digest is not proof.

Do not restrict discovery to current retrieval rows, active repositories or the
currently configured key. Those can lose or replace the context while the journal
retains it. Malformed retained data must fail migration explicitly; it cannot be
silently skipped or treated as clean. Missing source events require an explicit
repair path rather than a fabricated event/hash or a success-shaped receipt.

The backfill must work for a schema owner without BYPASSRLS. Keep every source
and new tenant table forced throughout maintenance. PostgreSQL supports
role-scoped policies and an explicit current-user role target; use temporary
owner-only SELECT policies for the source event/failure/fork tables and a narrowly
scoped owner INSERT policy for the new incident table. The implementation uses
those mechanisms under cratectl's existing exclusive schema transaction; named native
verification is retained in the exact5816checkpoint. See PostgreSQL 16's [row security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html)
and [policy definition](https://www.postgresql.org/docs/16/sql-createpolicy.html).

Create those temporary policies only after runtime transactions drain through
the schema gate. Remove every temporary policy before final schema admission;
the permanent single tenant policy and all FORCE flags must remain exact. Runtime
roles must never gain owner membership or migration privileges. Test a genuine
nonsuperuser/non-BYPASSRLS migration owner, scoped runtime access while admission
waits, and rollback after an error/interruption between policy creation and
cleanup. Large histories can require controlled maintenance; exceeding existing
time/work bounds must roll back rather than partially seed incidents or relax
enforcement.

## Conservative enforcement and explicit trust review

An unresolved incident with an unknown historical key must conservatively require
review for every configured checksum key in that tenant. A new source epoch,
repository removal, cache refresh, negative lookup or another repository must not
bypass it. An unaffected tenant remains independent. Check authenticated key
blocks first, then legacy review, before discovery, acquisition, renewal,
publication, negative fallback and final byte admission. Safe reader state can
expose that review is required without revealing an unrelated repository/module.
Current administrators inspect the original incident context and journal anchor.

Recovery is an explicit administrator decision to trust a separately reviewed
external authority key despite the unattributed historical incident. Record an
immutable disposition per incident and exact key; do not delete the incident,
rewrite its classification, reset a checkpoint or mark packages scanned/clean.
Reject any disposition for a currently authenticated blocked key. A different
authority with the same display name remains a different exact key. Reusing an
unknown old key cannot be proved safe from absent evidence; the operator's
external review and its limitations must remain explicit.

Require current administrator/repository authorization, exact current source
epoch/key/signed bootstrap, original incident sequence/hash, bounded review reason
and an external review reference/digest. Preserve idempotency and fingerprint
checks. Admission, immutable disposition and its synchronous journal effect share
the existing tenant write transaction; ordinary queue capacity must not erase a
confirmed disposition. No external delivery or asynchronous projection is implied.
Review one bounded incident/key binding at a time, or use an independently bounded
exact manifest. Unknown incidents and unresolved bindings continue to block that
key. Re-check current credentials and state on replay; a future genuine fork must
still block the key regardless of any earlier administrative disposition.

This is repository trust configuration for external artifact verification. It does
not issue keys, provide signing/custody, implement a CA/vault, rotate external
credentials or rehabilitate an external authority's cryptographic history.

## Required evidence before accepting the change

Use isolated prior-schema fixtures, clearly distinguished from actual old-binary
journeys. Exercise old labels after source/key changes and repository removal;
two tenants with identical coordinates/keys; a valid source-13 original fork that
must remain authenticated/blocked; orphaned or mismatched evidence; and malformed
history. Preserve original receipt, event and checkpoint bytes through maintenance
and no-op replay. Prove interruption rolls back both data and forced-RLS changes.

Real PostgreSQL normal/race tests must cover runtime immutability and unscoped RLS,
all common serving/work/fallback fences, current and expired credentials, reader
denial, exact incident/key/source review, idempotency conflict and lost-response
replay, full ordinary queues, cross-repository/tenant behavior, and actual
concurrent review/publication/fork outcomes. Keep all original tests and failures.
No partial approval or missing original evidence can count as verified.

Add bounded API/CLI/UI inspection and review with concrete impact preview, original
journal attribution, explicit external-trust language and retained outcomes. Native
browser interaction and separately tested real database enforcement are distinct
claims. Export verification must distinguish signed log proof from cratectl
incident attribution and operator trust decisions.

Rebuild a newly pinned, qualified clean native schema-13 baseline on GitHub and
extend the historical inventory/serializer/upgrade profiles together. The shared
lifecycle CLI bound must admit that pin and reject the new current/future schema.
Run every original client and required normal/race profile on native Linux amd64
and arm64. Keep x86 Chromium and the broader three-host source/fuzz lanes on
GitHub. Source-13 qualification, this plan and compilation alone are not passes
for the new migration or recovery path. The stopped primary remains schema 11
on its selected binaries unless the owner separately authorizes maintenance.


## Implemented candidate and acceptance limits

The draft appends immutable forced-RLS incident/review tables in schema 14 and
uses the current common key guard for all existing admission paths. Bare new
labels are also captured synchronously, independent of ordinary queue capacity.
Migration validates original tenant/sequence/hash links in 64-row pages with
64 KiB/event and 100,000-label bounds before removing temporary owner policies.
No database hashing extension or unforced interval is used. First thirteen
migration definitions remain frozen. Schema 14 is frozen as
`b1900b2f1e3fd96955b5a40e52e9dd0f37eb0303bfda513dd77f518dac25bcb5`.

The admin API, existing CLI transport and console support original incident
inspection, exact-current-state external trust preview/apply, lost-response
replay and immutable historical review/key/checkpoint retrieval. Retained Go
proxy configuration can choose a separately trusted key under mandatory checksum
enforcement; new creation and public protocol routing remain gated. See
[operator workflow](../go-checksum-inspection.md). Browser stand-ins exercise the
customer controls only; real PostgreSQL tests exercise authorization and durable
state separately.

Native acceptance must include nonsuperuser/non-BYPASS owner backfill across two
tenants, removed original source/no retrieval context, typed source-13 fork
exclusion, orphaned attribution, damaged-link and post-backfill rollback, runtime
immutability/forced-RLS refusal, review/source/key/checkpoint/credential fences,
concurrent review/fork and lost-response behavior. Broader full-chain journal
anchor export, large-history migration, full stock checksum-on proxy/group,
offline cache/install/export/backup/GC and all later goal outcomes remain open.
