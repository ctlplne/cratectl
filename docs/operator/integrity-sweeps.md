# Inspect pre-existing referenced bytes

Publication-time checks cover new work. A sweep inspects the current references
that already exist in a repository or tenant, including denied and unassessed
artifacts and retained OCI upload parts. It snapshots exact repository/digest/size
bindings; later publications do not silently enter or change that snapshot.

Use a tenant administrator credential. Preview up to 1000 targets:

```sh
bin/cratectl --token-file /private/path/admin.token --path '/api/v1/maintenance/integrity-sweeps?repository=packages&limit=100'
```

The preview has no effect and is not a reserved snapshot. POST
`{"repository":"packages"}` to `/api/v1/maintenance/integrity-sweeps` with an
8–128 character `Idempotency-Key`. Send `{}` for all repositories in this tenant.
Admission atomically saves the complete target set, audit, job and original
response. Repeating the identical key returns the same job, not another scan.

`--integrity-sweep-target-budget` defaults to 100000 distinct bindings per run.
This is an operator resource control. An oversized snapshot is rejected in full;
no partial run is accepted. Narrow the repository or adjust the operator budget
after checking database capacity. Snapshot admission holds the tenant mutation
lock and has the existing 30-second SQL deadline. Its production-scale cost
remains unqualified; do not assume a large snapshot has negligible impact.

Run the ordinary [worker](jobs.md) against the same object directory and runtime
database. The integrity lane reads one snapshot target per claim, yielding
between targets. Its object ceiling, pacing, timeout and concurrency settings
apply. Hashing happens outside the SQL lock. A process kill leaves the current
target unacknowledged for the next owner; stale generations cannot advance it.

Inspect `/api/v1/maintenance/integrity-sweeps/JOB_ID`. It returns the job and
separate `all_targets_assessed`, `integrity_clean` and `security_approval` fields.
Progress includes snapshot time, target/reference counts, pass number, current
ordinal, checked, verified and issue counts. `succeeded` means the inspection
finished; a run with corrupt or missing objects can finish with findings.
`security_approval` is always false. Policy continues to govern every download.

Read `/api/v1/maintenance/integrity-sweeps/JOB_ID/items?limit=100&after=0` to inspect
targets. Follow `more` using the last item's `ordinal` as `after`. Each target
reports artifact aliases, upload-part count, contradictory reference lengths and
the current pass's observation. Missing/corrupt bytes, inconsistent size
declarations, I/O failures, timeouts and byte limits remain explicit findings.
An empty snapshot has zero inspected targets; it proves nothing about other
scopes. Full observation history is `/api/v1/jobs/JOB_ID/observations`, paged by
generation; `ordinal` and `pass` bind each receipt to its snapshot target.

POST `{}` with an idempotency key to `/api/v1/jobs/JOB_ID/cancel` or `/retry`.
Cancellation retains already committed observations and prevents acceptance of
the in-flight target. A cancelled/failed run resumes at its saved ordinal.
Retrying a completed inspection starts another pass over the same immutable
snapshot and retains prior receipts. It cannot rewrite a contradictory snapshot
after metadata repair. To inspect repaired current references or new content,
request a new snapshot with a new idempotency key.

Repair must use an independently verified source of truth and preserve audit;
this worker reports findings and never edits or deletes storage. Its snapshot
does not enumerate unreferenced CAS or temporary files. Full storage inventory,
orphan reconciliation, scheduling/readback sampling, repair operations, holds,
retention, safe GC, S3 and consistent backup/restore remain required.
