# ADR 0025: durable recurring integrity samples

Status: accepted for the named qualification fixtures; broader scope remains open.

An administrator may configure a tenant-local recurring referenced-byte sample.
The schedule records an interval, repository scope, target count, authorizing
credential fence and monotonically increasing configuration revision. Changes
require an exact revision, reason and idempotency key. Public configuration
history omits the credential hash. Reapplying settings with a current credential
reauthorizes future admissions. Pausing affects future admissions; existing jobs
retain their own cancellation and recovery controls.

Workers check one due schedule at a time per tenant, independently from execution
lanes. Tenant mutation serialization, current worker/requester authorization and
queue capacity apply. The immutable reference snapshot, job intent, run receipt,
cursor, next due slot and journal event commit in one transaction. Another worker
cannot admit the same slot. An unresolved previous run prevents overlap. Queue
pressure defers the original slot with an explicit retry time. Credential expiry
or revocation blocks admissions until an administrator reauthorizes the schedule.

Targets rotate in repository/digest/size order, wrapping at the end. Each run
captures at most the configured target count from current artifact and retained
upload-part bindings, including denied or retired references. Existing sweep
workers hash those captured bytes under their normal budgets and persist immutable
observations. Later reference changes do not rewrite a captured set. Rotation is
deterministic sampling, not statistical randomness or a complete-volume claim.

Late slots coalesce into one run and record the number of skipped intervals;
there is no unbounded catch-up queue. A failed run remains visible. Subsequent
samples cannot turn its findings into a global clean verdict. Schedules do not
authorize repair, deletion, policy changes or security approval.

Run inspection and worker read/completion paths crosscheck mutable progress against
the immutable admission name, revision, due slot and coalesced-interval receipt.
Mismatch or missing identity fails closed. Inspection returns an explicit evidence
error; workers durably fail the invalid target without producing observations.
Automatic repair of corrupt database metadata is outside this operation.

Schema 6 adds forced-RLS schedule, immutable configuration revision and run tables.
Receipts 1–5 remain frozen. Upgrade requires controlled maintenance; rolling
compatibility, full-volume sampling, unreferenced-file scheduling, S3, retention/GC,
large-profile behavior and broader production recovery remain required.

The named clean source, artifact hashes, runtime records and limits are retained in
[`schedule-checkpoint.json`](../../evidence/2026-10-31/schedule-checkpoint.json).
