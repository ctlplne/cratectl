# ADR 0001: authoritative state and publication

Accepted 2026-10-28. Target Go 1.27.3, PostgreSQL 16.15 or later supported major,
filesystem for the initial single-node implementation, S3 for production, and
React/TypeScript/Vite for the console. PostgreSQL 16.15 is already cached on this
host and remains supported; its use avoids installing a host database. No Redis,
broker, secondary database or search service is justified yet.

All tenant tables force row-level security (RLS: the database filters rows even
when application code forgets a tenant predicate). The application role cannot
own those tables or bypass RLS. A separate owner connection runs migrations and
explicit bootstrap. Service tokens identify one tenant and role. Initial roles
are admin, writer and reader; finer identity controls remain required backlog.

Every mutation takes a tenant advisory transaction lock, records a hash-chained
event, updates authoritative references, and records an outbox job in the same
transaction. The lock serializes a tenant's chain; it is a correctness starting
point, not a demonstrated scale solution. First-party requests retain their
response and request fingerprint under an idempotency key. Native protocols use
coordinate/digest semantics. A different request under the same key conflicts.

Uploads stream through fixed buffers into an exclusive staged file. Length and
SHA-256 are checked, the file is synced, then atomically linked into a tenant
digest namespace and the containing directory synced. Only then can PostgreSQL
publish a reference. Crashes may leave unreferenced bytes, never a committed
reference to a knowingly incomplete staged file. Cleanup is not implemented and
must not delete anything speculatively. Local storage requires durable POSIX-like
rename/link/fsync behavior; multi-node and S3 are unqualified until tested.

Policy is checked from authoritative state on each read; projections cannot
authorize downloads. Initial quarantine blocks serving, and a manual decision
is labelled manual rather than a scanner verdict. There is no scanner yet.

Opaque tokens and digests use `internal/crypto`. The owner's 2026-11-04 scope
amendment in `GOAL.md` section 4.1 supersedes the earlier native-signer plan:
artifact/evidence signing uses customer-controlled external tools or providers
through a bounded adapter. No cratectl signing/custody service is in scope.
TLS is mandatory except an explicit loopback development mode.
