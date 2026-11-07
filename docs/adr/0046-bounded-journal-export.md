# Bounded journal export with a separately trusted checkpoint

Status: implemented and qualified at a3d8df2 within the bounded native profiles.
Both actual Linux hosts pass all257PG functions normally/race and683baseline
assertions; three native hosts pass50fuzz/source gates. Main x86 Chromium passes
18workflows/141checks, including three explicit UI response stand-ins with actual
store/CLI enforcement separately tested. The original ca56447 invalid-JSON
oversize fixture failures remain preserved under DEFECT0127; valid oversized JSON
replays the same limit assertion normally/race without schema or bound changes.
No broad export/provider/large-history/readiness verdict. The later journal-to-Go
attribution extension remains native unverified.
All 450 artifact capabilities, 41 families and later GOAL stages remain. This
adds repository evidence verification under section 4.1, without a signing/key
custody service. Source migration definitions 1–14 remain frozen.

## Problem and boundary

The journal preserves exact original payloads and local hash links. Its prior
legacy list endpoint selected up to 1,000 full events without a response-byte
budget. Go failure inspection correctly requires a separately trusted journal
or manifest digest, but no complete product workflow currently verifies that
journal path offline. A hash returned beside its payload is not independent
attribution, and a current database head alone is not an authenticated anchor.

Add a bounded read-only checkpoint and immutable-range page API for current
tenant administrators. The checkpoint is explicitly unsigned. Customers must
retain/authenticate its tenant, sequence and hash independently, for example with
their existing external signing tool/provider or another trusted record. cratectl
must not invent a signer or report that an unsigned server response authenticated
itself. External signing/provider adapters remain separate committed work.

## Immutable range and memory bounds

Each page binds tenant, the exact prior sequence/hash, an exact retained terminal
sequence/hash and its original events. Keep one repeatable-read, forced-RLS
snapshot per page and check current credentials/administrator authority. Every
page checks the same retained terminal anchor; later journal appends do not move
it. A gap, changed tenant/sequence/link, missing head or mismatched hash must fail
explicitly before response headers. No partial page is a pass.

Read bounded event size/hash metadata before fetching selected payloads. Bound
row count and total response bytes separately; a count alone does not bound
memory. Select no unbounded text from damaged rows. Events that exceed the
supported single-event budget produce an explicit limit error. A subsequent
streaming/large-event path and large-history qualification remain required;
unsupported old history cannot be silently skipped or called clean.

The existing list should gain equivalent byte bounds without changing its
original payload bytes. Each change needs meaningful real-PostgreSQL coverage:
current/expired/reader/cross-tenant authority, immutable range after concurrent
append, gaps/tampering, one oversized event, per-page byte/count limits and exact
lost-page re-read. No migration or retained-primary maintenance is required for
these read-only surfaces.

## Offline verification

Use a versioned sequence of bounded JSON page records. A CLI command reads an
owner-private regular file and separately supplied expected tenant/start/head
bindings, verifies every original payload/link and consecutive sequence, and
requires the final provided checkpoint. Bound each frame, event, page count and
total input while streaming. Empty, truncated, duplicated, reordered, trailing,
wrong-tenant or wrong-anchor input must not emit a success receipt.

Cryptographic primitives stay in internal/crypto. Hash exactly the retained
previous-hash string, newline and original payload bytes; do not reconstruct or
normalize old events. An authenticated range proves integrity relative to the
provided checkpoint. It does not prove that arbitrary claims in event data were
true or that an external delivery happened. Selecting a known Go failure event
can establish its exact retained evidence digest, still separate from replaying
the original checksum authority signatures and applying package policy.

Add API/CLI/operator documentation and a console route to the bounded workflow,
with unsigned-anchor language, denied/empty/loading/limit states and exact integer
handling. Native x86 Chromium may use declared response stand-ins for UI claims;
real database and offline cryptographic behavior require separate tests.

Implemented surfaces: `GET /api/v1/audit/checkpoint`,
`GET /api/v1/audit/export`, `cratectl journal-export` and
`cratectl journal-verify`; the older audit list returns explicit advancing
cursors. See [operator instructions](../journal-export.md) for the exact bounds,
canonical JSONL format, private-file behavior and external trust requirement.

## Qualification and subsequent work

Use ARM unit/stand-in/parser tests and bounded fuzz locally. Compile/vet database
suites locally; run actual PostgreSQL normal/race, stock clients, x86 Chromium and
all original selected profiles on their GitHub native hosts. Retain exact source,
input and artifact identities and all first failures. No skipped test is a pass.

This is a foundation for independently attributed export. It does not finish full
Go package/proof/trust/policy bundles, external signature verification/adapters,
consistent backup/restore, export/GC leases, offline cache/install, conditional
refresh, stock checksum-on proxy/group or any later GOAL requirement. DEFECT0126
native-client trust-state investigation remains separate and failed; it does not
remove independent repository implementation work.
