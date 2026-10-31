# Authorize future OCI retirement runs

A one-time retention approval covers one exact target set. A schedule is separate
approval for future complete target sets selected by one exact policy revision
and repository source revision. Each admitted run still records immutable targets
and outcomes. It creates retained tombstones, preserves bytes and decisions and
reports zero reclaimed storage. Read [retention](retention.md) first.

The management API, CLI, console and dedicated stock ORAS/CLI journeys have
development preflights. Actual due-slot coalescing, process restart, cancellation,
credential expiry/revocation, current policy/source approval and recovery after
worker SIGKILL are observed. Exact clean production/race qualification remains
pending. The latest qualified source remains the schema-7 retention checkpoint.
No broad release readiness is established.

In Storage → Retention, load an OCI repository, inspect a policy and choose
**Inspect automatic retirement**. Configure the interval and complete manifest
limit, review the displayed current policy/source revisions, and explicitly
acknowledge future captures. The acknowledgment starts unchecked each time.
Preview reads the proposed configuration without saving it. Apply authorizes
future complete sets under those exact revisions and your current credential.

If an approval reply is lost, **Retry same automatic retirement request** sends
the original bytes and idempotency key. Editing is disabled while the outcome is
uncertain. If you close the dialog, inspect current configuration and its history
before another approval. A concurrent replacement rejects a stale preview;
refresh the current state before reviewing a new approval.

The console distinguishes paused, enabled, deferred and blocked configurations.
An enabled due configuration alone proves no retirement. **Inspect last scheduled
run** opens immutable capture identity, actual outcomes and common verified
restore. **Review current retirement schedule** returns to the current approval.
Configuration and run histories use bounded pages. Preparing historical settings
copies cadence, limit and enabled state; current bindings and fresh consent govern
the new approval. Revisions beyond exact browser integer precision require the CLI.

Read the policy endpoint for its current revision and repository detail for
`source_revision`. Read the policy's `/schedule` endpoint for its schedule
revision; a missing schedule starts at revision zero. Save complete settings in
a private request file, for example:

```json
{
  "expected_revision": 0,
  "expected_policy_revision": 1,
  "expected_source_revision": 0,
  "interval_seconds": 3600,
  "max_targets": 1000,
  "enabled": true,
  "authorize_future_retirements": true,
  "reason": "Retire old unheld releases under the reviewed policy every hour",
  "run_immediately": false,
  "dry_run": true
}
```

```sh
cratectl --config /private/client.json --method PUT \
  --path /api/v1/repositories/containers/retention-policies/monthly/schedule \
  --body-file /private/schedule.json --idempotency-key schedule-preview
```

Review the returned complete policy, source revision, interval, maximum target
count and authorizing actor. `dry_run` saves nothing and admits no work. Remove
it or set it false, then apply with an idempotency key. Identical retries confirm
the original configuration rather than granting another revision. Enabling must
explicitly acknowledge future retirement. Saving an ordinary retention policy
continues to authorize no automatic work.

A running worker admits one current capture when database time reaches the due
slot. Several missed intervals coalesce into one capture with an immutable count;
they do not produce a burst of old runs. The entire live canonical manifest set
must fit `max_targets` and the existing metadata budget, including protected
targets. No truncated or partial set is admitted. An active manual or scheduled
run of that policy also defers automatic admission.

Inspect the schedule's current `next_due_at`, `retry_at`, `blocked`, `last_error`
and `last_job`. Configuration history is at `/schedule/history?after=0&limit=50`;
continue from the last revision. Scheduled run history is at
`/schedule/runs?after=0&limit=50`; continue from the last job's sequence prefix.
The ordinary policy `/runs` history also includes scheduled runs. Common run
detail and target outcomes remain the authority for actual retirement effects.

`maintenance_queue_full`, `events_queue_full`, `plan_budget_exceeded`,
`repository_unavailable` and `previous_run_active` defer without consuming the due
slot. Inspect capacity, approved limits, repository state and prior job outcomes.
The worker retries these states after a delay. An oversized capture never implies
that some targets were silently selected.

`requester_authorization_unavailable`, `policy_changed` and `source_changed` block
new admissions. Use a current administrator credential, read current policy and
source revisions, preview and explicitly save a new schedule revision. Retrying
an old job does not replace its original authority.

To pause, replace the exact schedule revision with `enabled: false`,
`authorize_future_retirements: false` and `run_immediately: false`. Supply the
current policy/source revisions and remaining complete settings. Pause or any
schedule replacement stops unprocessed targets from its earlier scheduled runs.
Such a worker job records `retention_schedule_changed`; earlier outcomes remain.
Cancelling one run does not pause future due slots. Manual one-time approvals
retain their existing meaning. Recover retired content through verified restore.

Schema 8 adds forced-RLS schedules and immutable configuration/due-slot receipts
and preserves migrations 1–7. Upgrade requires controlled maintenance. The owned
primary reached schema 8 during a controlled clean-candidate campaign. That
candidate was rejected on a harness timing assertion, so the latest qualified
source remains schema 7 pending the complete clean replay. Other rules/formats,
calendar schedules, legal-hold administration, physical GC, release/replica/
restore protections, providers/platforms, fault/clock/scale and production
recovery remain committed work.

The dedicated development campaign is
`python3 scripts/conformance_retention_schedules.py --require-clean-build`.
It requires matching clean current binaries, the retained qualified schema-7
server at `.cache/retention-final-production/cratectld` (source `6cac885`), stock
ORAS 1.3.6, and the owned PostgreSQL owner/runtime DSNs in the existing private
environment. Port 38443 must be free. The campaign creates an isolated database;
it does not migrate the database named by the supplied DSNs. It leaves registry
and worker stopped across two real due slots, so it takes over two minutes.

Each native command writes a permanent private log, including expected failures
and timeouts, under `.private/retention-schedule-conformance/RUN`. Process logs,
raw command output, credential files and the isolated database remain retained.
Public evidence records source/build identities, command statuses and log paths.
Owned SQL ages artifact fixtures and briefly blocks a worker claim or second
outcome; schedule clocks, credential expiry and worker lease expiry use actual
elapsed time. These declared faults do not provide product metadata repair.
