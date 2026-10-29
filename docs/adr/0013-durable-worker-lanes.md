# Durable worker lanes and exact-byte integrity

Preserve the journal's transactional outbox and turn its pending intent into
bounded executable work. Existing event jobs become `event.project` work in the
`events` lane. Publication records separate `storage.integrity` jobs in the
`integrity` lane for exact repository/digest/size bindings. Deduplicate aliases
within one mutation. A deferred journal foreign key permits intent creation
inside the same transaction before its event is appended. References, event,
idempotency response and work either commit together or roll back together.

Each lane has persisted per-tenant capacity, running concurrency, attempt and
backoff budgets. Admission counts outstanding work; failed/succeeded/cancelled
history does not consume ready-work capacity. Saturation returns actionable 503
and rolls back publication. A source completion rejected by capacity abandons
only its still-current retrieval fence in an audited local transaction, enabling
immediate retry after capacity repair. It never publishes partial references or
waits out a lease for work known not to have committed.

Workers use the nonowner runtime role and forced RLS. Dedicated `worker` tokens
cannot authenticate to the public API; ordinary API credentials cannot execute
worker operations. Reauthenticate after taking the tenant lock on every claim,
heartbeat and completion. Compare expiry with `clock_timestamp()`, because
transaction-start time can precede a lock wait. Credential bootstrap, emergency
revocation and job control are audited local transactions that do not require
room in an already-full outbox. Worker lifecycle audit events do not recursively
enqueue themselves.

Claims increment a generation and receive an opaque random lease token. Renew
only a live current owner. Completion checks token, generation, worker and
deadline under the tenant lock. Expired, cancelled or replaced owners cannot
record an effect. Recover expired claims within the persisted attempt budget;
retry timing survives restart. Running cancellation remains `cancel_requested`
until acknowledged or recovered after expiry. A terminal retry preserves total
attempt history and starts a fresh attempt cycle. Idempotent management control
replays its original response; clients read current state separately.

Reserve independent execution slots for each implemented lane. Within each lane,
rotate across the explicitly configured tenant identities. Persisted running
limits apply across processes. Local round robin, separate slots, paced I/O,
fixed buffers and per-attempt deadlines bound interference. This establishes a
single-host foundation, not a complete multi-host fairness or scale result.

The event handler verifies its source event hash and previous link, then commits
a bounded activity projection with job completion. Its cursor is a durable
completion position, distinct from the source sequence, so a late projection is
not skipped. Projections never authorize artifacts; the journal is authoritative.
Local credential and job-control audit events remain in the journal rather than
this source-event projection.

The integrity handler streams at most declared size plus one through SHA-256,
with a byte ceiling, pacing and cancellation. It observes verified, missing,
corrupt, superseded, I/O, limit or timeout results. Recheck reference identity at
completion. Observations are immutable per attempt and never approve content or
change manual policy. Serving still verifies bytes and current graph policy.
An unreferenced old binding becomes superseded, never a claim about new bytes.

Real PostgreSQL tests cover RLS, purpose separation, admission rollback,
distributed running limits, fences, cancellation, late activity, lock-wait expiry
and source-capacity recovery. A native two-tenant API/CLI journey kills and
restarts actual worker processes, checks reserved lanes/round robin, injects and
repairs same-length corruption, cancels active hashes, rolls credentials and
restarts the registry. Exact source/binary evidence is recorded separately.

Scanners, webhooks, replication, GC, migrations, S3, orphan reconciliation,
retrieval/upload reapers, global multi-host scheduling, retention, production
upgrade/restore and the full security/scale campaign remain required. These
handlers do not establish external exactly-once delivery or a clean security
assessment. No broad capability or readiness verdict closes.

Primary references observed 2026-10-28:

- [PostgreSQL 16: current time functions](https://www.postgresql.org/docs/16/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT)
- [PostgreSQL 16: advisory and row locks](https://www.postgresql.org/docs/16/explicit-locking.html)
- [PostgreSQL 16: forced row security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html)
