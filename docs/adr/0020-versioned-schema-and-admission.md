# Versioned schema changes and transaction admission

The existing migrator replays cumulative DDL on every invocation. A retained
failure shows its repository/token lock order can deadlock a live upload check.
Replace repeated application with immutable checksummed migration receipts. The
first version adopts the existing schema scripts and exact RLS/grants as a frozen
baseline. Add later changes as new steps; modifying an applied checksum fails.
Unknown versions, gaps, checksum changes and unsafe RLS/policy drift fail before
application. A current database is checked through a read-only path without DDL.

The receipts are database-level administrative metadata in the private schema,
not tenant business records. Runtime cannot read or change that table directly.
A fixed SECURITY DEFINER function returns only version/checksum and safety state;
its search path is pinned and execution is limited to the runtime role.

New runtime transactions, authentication and owner identity operations acquire a
shared database advisory gate before beginning their data transaction. A migrator
acquires the exclusive gate before DDL. New requests decline admission while it
waits/applies, and admitted transactions drain. Acquire the shared session lock
before a repeatable-read snapshot, then release it after commit/rollback; never
return a pooled connection carrying a session lock. Cancellation/error cleanup
unlocks with its own bounded context or destroys the connection.

The gate covers database transactions, not an entire network transfer. Real schema
changes can interrupt a staged transfer when its next fenced callback is denied;
no stale effect may commit. Current-schema replays do not take the exclusive gate.
Runtime checks known schema compatibility and safety on every transaction; newer
or drifted schemas reject operations with actionable 503 responses, not 401.
The console must retain its credential during maintenance and allow retry.

Pre-gate binaries do not participate. Initial adoption of an existing unversioned
database therefore requires explicit --adopt-legacy with registry/worker traffic
stopped. This is not a zero-downtime adoption or a qualified rolling upgrade.
Future expand/contract steps, compatibility ranges, transfer draining, backups,
downgrade/recovery and independent multi-node rolling campaigns remain required.

Plan/status output contains versions, checksums, pending steps and requirements,
never database credentials. Apply is transactional: schema, role grants, RLS and
its receipt commit together. Interrupted/failed application retains no partial
receipt or schema. Concurrent migrators recheck after acquiring the gate. All
work uses owned real PostgreSQL fixtures, with deterministic lock/cancellation,
no-op, checksum/drift, legacy adoption, interruption and active request tests.
