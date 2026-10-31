# Schedule recurring referenced-byte checks

Open **Storage → Recurring integrity → Create integrity schedule** as a tenant
administrator. Choose a name, optional repository, interval, target count and
reason. Preview, then apply the configuration. Select **Make the first slot due
immediately** to start without waiting one interval. The worker must be running.

Each run checks a bounded sample of retained repository/digest/size bindings.
Aliases share a target when repository, digest and size agree. Denied, retired,
held and retained upload-part bindings remain eligible. A group endpoint does not
own bytes; select a hosted/proxy repository or leave the scope empty for the
tenant. A scoped repository must remain available for admission.

Repository, digest and size identify a sampled binding. A representative path may
be an alias or a retained upload-part name; it is not necessarily a native download
URL. For repair, select the actual retained artifact path through Packages or the
repository artifacts API.

Targets rotate in repository/digest/size order, continuing after the previous
cursor and wrapping at the end. This is deterministic sampling. References added
behind the cursor enter a later wrap. Each run records its actual immutable set;
later reference changes do not rewrite it. SQL deadlines bound admission work,
but grouping can still scan many rows. Large-profile cost remains unqualified.

The interval is 60–31,536,000 seconds. A sample contains 1–1,000,000 targets and
must fit the registry's configured sweep target budget. Workers use their existing
object-size, hashing-rate, timeout and queue limits. A dedicated admission loop
visits configured worker tenants in turn, at least one second apart. Due time is
intent, not a guaranteed execution deadline. Multiple workers serialize admission
in PostgreSQL. Multi-host latency and global fairness remain unqualified.

Inspect a schedule for current admission state, due/retry times, configuration
history and sample runs. **Inspect captured sample** shows exact digests and
observations. A completed run can contain missing, corrupt or inconsistent bytes.
An empty run completes its empty captured set without claiming byte verification.
A clean nonempty sample applies only to its captured targets. No sample grants a
security approval or declares the full tenant volume healthy. Earlier findings
remain visible after a later clean sample.

If inspection reports `schedule_evidence_unavailable`, stored progress disagrees
with the immutable admission identity. It cannot be treated as current verified
evidence. The console labels any retained view as an older observation. Workers
fail that invalid target without adding verification receipts. Investigate the
database evidence and verified recovery sources; automatic metadata repair is
unavailable. A new idempotency key does not repair stored evidence.

Use **Packages → Repair bytes** with an independently retained exact copy to
recover a missing/corrupt binding, then admit another sample or retry the original
captured set through its job. See [byte repair](byte-repair.md). A retry of a
completed sample creates another pass over that same captured set; it does not
replace the recurring schedule or advance its rotation cursor.

Admission handles interrupted or delayed operation as follows:

- One unresolved run prevents another run of that schedule. Inspect its durable
  job and resolve cancellation, retry or uncertain state before expecting another
  sample. Other schedules retain their independent queue admission.
- A full integrity queue defers the original slot with a retry time. It does not
  consume the slot or rotation cursor. Configure capacity through the existing
  [job policies](jobs.md).
- Late intervals coalesce into one run. The receipt records how many overdue
  intervals were skipped; workers do not build an unbounded catch-up queue.
- The job, captured set, due-slot receipt, cursor, next due time and journal event
  commit together. A failed database transaction leaves the original slot ready
  for retry. Original requester authorization is rechecked after final writes.

Future admissions use the administrator credential that last configured the
schedule. Expiry or revocation blocks new admissions. Connect with a valid
administrator credential, choose **Edit and reauthorize**, preview and apply.
This creates another configuration revision and updates the authorizing actor.
Credential values and execution hashes are never returned by the schedule API.
Previously admitted samples remain delegated read-only integrity work under the
worker credential; cancel an existing job separately if it must stop.

Pause by editing the schedule and clearing **Enable future admissions**. This
preserves configuration, rotation and run history. Every applied replacement
resets the next due time to commit time plus the interval, or commit time when
immediate admission was selected. Rotation continues when repository scope is
unchanged; a scope change resets it. An idempotency replay confirms the original
response and does not reapply settings or reauthorize a newer revision.

The CLI uses the same API. Save this plan in a private JSON file:

```json
{
  "expected_revision": 0,
  "repository": "containers",
  "interval_seconds": 3600,
  "sample_size": 100,
  "enabled": true,
  "reason": "Hourly retained-byte integrity sample",
  "run_immediately": true
}
```

```sh
cratectl --config /private/client.json --method PUT \
  --path /api/v1/maintenance/integrity-schedules/hourly \
  --body-file /private/schedule.json --idempotency-key schedule-unique-key
```

Add `dry_run: true` to preview. Read the named endpoint for the exact revision
before replacing settings. Collection pages use `?limit=50&after=LAST-NAME`.
History uses `/{name}/history?after=REVISION&limit=50`. Runs use
`/{name}/runs?after=SEQUENCE&limit=50`, where sequence is the numeric prefix of
the last returned job ID. Continue while `more` is true. These are bounded live
pages, not a fixed multi-page snapshot. The maximum page limit is 100.

Upgrade with registry and workers stopped. Schema 6 preserves receipts 1–5 and
adds forced-RLS schedule, immutable configuration and run tables. Earlier
runtimes reject the new schema. Controlled maintenance is required; rolling
compatibility, backup/restore and downgrade remain open. Scheduling unreferenced
filesystem inventory, randomized/full-volume sampling, calendar schedules, S3,
retention/GC, alerts, other platforms and production-scale behavior remain work.
