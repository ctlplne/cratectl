# 0051: Reconcile expired export sessions through tenant workers

Date: 2026-11-07. State: named source-15 worker cases verified at fca2d4a/15a49d3.

See the [native Go checkpoint](../../evidence/2026-11-07/go-module-15a49d3-native-checkpoint.json).
This decision describes the original schema-15 worker. [ADR0053](0053-indexed-export-expiry.md)
adds schema-16 indexed lookup; its new native proof remains pending.

An expired export stops serving immediately, but its payload pins remain until
a terminal transaction records the expiry. Relying on an administrator to open
each session leaves unattended sessions consuming capacity indefinitely.

The existing worker now visits its configured tenants in a separate bounded
round-robin loop. Each visit selects at most one due open or acknowledged
session, using PostgreSQL time. Visits are paced by the greater of the worker's
poll interval and one second. Each attempt has the existing job timeout capped
at 30 seconds. Busy event, integrity or maintenance execution lanes cannot
starve this loop; database capacity and credential failures still stop progress.

The worker uses its dedicated credential, the ordinary nonsuperuser runtime
connection and forced tenant RLS. It reauthenticates after acquiring the tenant
mutation fence and before committing. Its authority is expiry only: it cannot
renew, acknowledge, collect policy or package bytes, or grant source access.
Expiry remains possible after the creating administrator is revoked or the
repository is retired; those changes must not retain expired collection leases
forever. The configured worker credential must itself remain current.

The transaction advances the session generation, marks it expired, and appends
the worker-attributed `go.export.changed` event and its projection job intent.
Queue saturation or any commit failure rolls back the entire transition,
retaining payload protection. The committed terminal state supplies automatic
operation idempotency: concurrent workers and a repeat after a lost response
cannot produce a second expiry for that generation. This internal operation has
no HTTP request or client idempotency receipt. Original creation receipts and
immutable manifest/item identity remain unchanged. Manifest roots persist;
other active exports and artifact/upload references keep their own protection.
This grants no physical deletion permission.

No schema change is needed. All fifteen migration definitions stay frozen.
Three new real-PostgreSQL regressions cover saturated-queue rollback and roots,
concurrent workers and one event/job, active-session preservation, wrong-purpose/
tenant/revoked credentials, and the actual worker loop reaching expiry while
the observer uses only the read-only list (never the auto-reconciling GET).
Owned timestamp aging creates due rows; it does not qualify real clock shifts.

Local ARM build/unit/race/lint and tagged compile/vet are development evidence.
Execute all 271 PostgreSQL functions and 93 named Go functions normally and
under race on both actual GitHub Linux architectures, with the original client
and upgrade profiles. This does not qualify large tenant/session backlogs,
independent hosts, real clock faults, complete export closure/import, physical
GC, backup or broad readiness. The query returns one bounded result but large
retained history still needs measured indexing and throughput work.
