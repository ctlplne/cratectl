# Hold inventory and immutable history

Status: accepted for the named clean production/race fixtures. Full hold-case,
legal-retention, provider/platform and production-recovery scope remains required.
See `evidence/2026-10-31/hold-checkpoint.json`.

Administrators need to discover active, expired and released holds across their
tenant, inspect the original hold/release receipts, and recover a hold while its
repository is suspended or retained in removed state. Serving and destructive
operations retain their existing repository, policy and hold protections.

Read immutable hold/release snapshots from the existing transactional journal.
Do not synthesize historical actions or expiry events. Expiry changes the current
observation; the original timed-hold receipt remains unchanged. Released holds
remain discoverable through their actual journal records.

Append migration 9 with indexes for the current lifecycle list and journal lookup.
Keep all eight existing receipts and tenant RLS unchanged. No historical tenant
data is copied or rewritten. Each page has row, byte, query and database execution
bounds. Current credential and administrator authority apply to every page.

Use encrypted authenticated continuations bound to tenant, actor, role,
credential, endpoint and filters. A global position combines the bounded repository
and canonical path. Its 2,112-byte bound does not increase existing endpoint limits.
Pages are live observations; they are not a multi-page snapshot.

Hold placement/release can inspect retained repository metadata under current
administrator authority. This grants no native serving, deletion or restore bypass.
Revisions and idempotency retain their existing transactional behavior.

This completes discovery/history foundations for the existing per-reference hold.
Multiple independent cases, case-scoped releases, bulk administration, other
formats, legal-retention workflows, production recovery and physical GC remain
committed scope. A hold is not a legal-compliance verdict.
