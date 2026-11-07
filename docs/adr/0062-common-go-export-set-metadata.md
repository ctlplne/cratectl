# 0062: Plan selected Go exports in one database snapshot

Date: 2026-11-07. State: implementation and native qualification in progress.

The qualified index authenticates several separately created historical exports.
It cannot establish one common source snapshot. Start the common-snapshot path
with a bounded metadata planner and explicit unsigned API/CLI preview. Durable
set creation, physical verification/staging, session lifecycle and full closure
remain the next parts of this same outcome.

Accept1–256distinct hosted module/version selections, each with an explicit
repository and expected source revision, a common60–3600second lifetime intent
and positive declared-byte budget through64GiB. Refuse duplicate coordinates,
including competing sources in different repositories. Preserve selected order.
Use the existing administrator/current repository access/policy path inside one
`Store.Tx(..., false)` repeatable-read/read-only transaction. Capture one DB clock
and journal head for every root. Never call the per-version planner in separate
transactions and label the resulting mixture consistent.

Bound request data to256KiB, each canonical child manifest to32KiB, the combined
canonical metadata to8MiB and the complete planning transaction to30seconds.
Existing global request slots, server transfer timeouts, SQL statement budgets,
tenant RLS and runtime role admission stay in force. Bound root count before
allocating typed structures when decoding the larger manifest. A whole-array
struct unmarshal could otherwise allocate hundreds of MiB for empty objects
before checking the count. Header values and individual children are bounded
separately. Reject null/duplicate/alias/unknown fields and noncanonical manifests.

Expose only `POST /api/v1/go/export-sets/preview`, also usable through the normal
management CLI. Return the complete canonical manifest/object identity and
explicit `physical_objects_verified=false`/`durable_session_created=false`.
Current admission, checksum authority and dependency closure remain false. No
object is opened, no reference is pinned and no journal/job/receipt is written.
A preview is unsigned; independently authenticated creation and current fenced
revalidation are still required before this can become a durable export.

Require native PostgreSQL proof of one actual repeatable-read view while a second
connection commits a late-member policy denial. That admitted read must retain
the old coherent view; a fresh request must see the denial and emit no partial
selection. Also exercise exact byte ceilings, late epoch/missing/member denial,
wrong role/tenant, cancellation, no durable effects, actual API intake/approval
and every original native regression. Local parser/race/fuzz/HTTP stand-ins and
tagged compilation are separate from actual Linux x86/ARM integration proof.

Preserve all16migrations and the stopped schema11primary. Freeze an actually
qualified schema16baseline before any future appended migration for durable
sets. All14export cases,7environments and450capabilities/41families/laterGOAL4.1
scope remain required. This metadata preview neither completes the bundle nor
creates a signing/CA/vault/identity platform.
