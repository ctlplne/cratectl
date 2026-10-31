# ADR 0026: policy-driven retained retirement

Status: backend implemented locally; console and clean-candidate qualification pending.

Retention policies select canonical OCI manifests by minimum age and the number
of newest live manifests to keep per image. Policies can protect every live tag.
An administrator supplies a reason, exact configuration revision and idempotency
key. Configuration history is immutable. Other format adapters retain their full
required lifecycle scope; this change builds on the existing OCI lifecycle.

A preview records a database-clock evaluation time, source revision, exact
bounded manifest set, lifecycle revisions, tags, strong parents and eligibility.
Applying requires that preview's digest and time within five minutes. Admission
recomputes the plan under the tenant mutation lock. A changed plan requires a new
preview. Oversized plans fail rather than silently truncating selected content.

Admission commits immutable run and target records, a maintenance job, journal,
outbox and idempotency response together. Authorizing credentials live only in
private execution columns and never in public job payloads or journal data.
The worker reads immutable run records, rather than mutable job progress, as its
authority. Each target commits its tombstone, immutable outcome and journal in
one transaction, with current worker and original administrator authorization.

Execution rechecks policy/source revision, repository availability, content and
lifecycle identity, age/newest retention, live tags, holds and strong incoming
references. It may retain more content than the approved plan; it never expands
the selected set. Even when tag protection is disabled, a changed tag set requires
a new preview instead of hiding a binding absent from the approved impact.
Changed policy or requester authority stops further execution.
Cancellation and retry preserve already committed outcomes and resume only
remaining targets. A completed retry cannot repeat retirement effects.

Retirement uses the common tombstone and restore path. It preserves CAS bytes,
security decisions, upload parts and history, and reports zero reclaimed bytes.
It does not authorize physical garbage collection. Future reclamation must also
protect pending writers, transfers, retained references, release/replica interests
and consistent restore points before erasing bytes. Scheduled policy execution,
additional selection rules and formats, physical GC, platforms, scale and full
production recovery remain committed work.

Schema 7 adds forced-RLS policies, immutable configuration revisions, runs,
targets and outcomes. Preserve migrations 1–6. Upgrade requires controlled
maintenance and rejects earlier runtimes; rolling compatibility remains open.

Backend failures and development replays are retained in
[`retention-backend-preflight.json`](../../evidence/2026-10-31/retention-backend-preflight.json).
