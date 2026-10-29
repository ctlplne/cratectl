# Immutable upload parts and bounded lease recovery

OCI chunk bodies previously streamed into one mutable file while a tenant write
transaction held its journal lock. A slow client delayed unrelated mutations;
moving that I/O outside the lock alone would allow an expired writer to truncate
a replacement writer's bytes.

New sessions reference immutable SHA-256 chunks in `upload_parts`. Each operation
claims a generation, secret token and current-clock deadline under the tenant
lock. Body I/O, legacy prefix import and final assembly happen outside that lock.
A heartbeat rechecks the credential, repository write grant and operation fence.
The final short transaction rechecks them, inserts part references and advances
the offset atomically with audit/work intent. Final publication uses the same
artifact/policy path. Stale writers can leave unreferenced bytes; they cannot
advance an offset or alter another operation's chunks.

Assembly opens one part at a time, validates its exact length and digest, and
streams into a new durable object. Part count, metadata bytes and total object
bytes are bounded. An old session imports precisely its acknowledged prefix;
the original file, including an unacknowledged tail, remains unchanged. Stop old
registry writers before applying this development migration. Rolling production
upgrades still require qualification.

Proxy fills also renew their exact generation/token lease and current read grant.
Renewal cannot resurrect an expired lease. Completion checks its deadline again
after preparing metadata and references; an expired completion rolls back.

Administrators may request `leases.reconcile` work in the independent maintenance
lane. The request's database-clock cutoff is fixed. Every bounded page checks
current eligibility under the tenant lock and atomically records its effects,
audit and cursor. Recovery releases only expired retrievals/upload operations
at or before the cutoff, or expires an idle upload session. It advances fences,
preserves acknowledged offsets and retains all bytes. A live heartbeat, newer
generation, cancellation or expiry after the cutoff prevents a stale recovery
effect. Successful pages yield to other ready work and reset only the consecutive
failure budget. A redrive resumes its cursor and cutoff; a new request starts a
new scan.

This is lease metadata reconciliation. A full historical integrity sweep, CAS
inventory/orphan reconciliation, holds, retention, safe GC and restore remain
required. No worker here physically deletes a byte or approves security policy.
