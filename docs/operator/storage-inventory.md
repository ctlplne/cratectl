# Account for retained filesystem bytes

An inventory walks this tenant's supported local filesystem layout, checks all
observed regular CAS objects, and checks an immutable snapshot of current artifact
and retained upload-part references. It includes unreferenced CAS files, staged
files and legacy uploads. It never edits or deletes an artifact byte.

Use a tenant administrator credential. POST `{"page_size":100}` to
`/api/v1/maintenance/storage-inventories` with an 8–128 character
`Idempotency-Key`. `{}` chooses a bounded default page. The response contains a
job ID, storage-root fingerprint and reference snapshot. Reusing the identical
key returns the original response, including after storage or operator settings
change. The dedicated worker runs the job in its integrity lane against the same
runtime PostgreSQL and local object directory.

List inventories and inspect a run:

```sh
bin/cratectl --token-file /private/path/admin.token --path '/api/v1/maintenance/storage-inventories?limit=100'
bin/cratectl --token-file /private/path/admin.token --path /api/v1/maintenance/storage-inventories/JOB_ID
bin/cratectl --token-file /private/path/admin.token --path '/api/v1/maintenance/storage-inventories/JOB_ID/items?area=cas&limit=100&after=0'
```

Follow `next` for job inventory. Entry pages return `more`; advance `after` using
the last item's `ordinal`. Areas are `root`, `sha256`, `cas`, `staged` and
`uploads`. Names have an exact `name_b64` identity and a readable display name.
An unsupported or disappeared entry remains visible. Links are never traversed.
Unexpected nested layouts prevent `supported_layout_accounted`; their children
are not silently treated as checked.

Each item records its observed size, filesystem identity, modification time and
reference counts at the walk. Current artifact/upload-part counts are reported
separately. A file unreferenced during enumeration can become referenced later.
Neither count authorizes deletion. `safe_to_delete` and `security_approval` are
always false. Pending transfers and future hold/replica/retention roots require
their own lifecycle checks before any cleanup exists.

The walk is live, not an atomic volume snapshot. New entries behind completed
cursors may need another run. Metadata-to-hash file replacement or mutation is a
`changed` finding. A different configured root fingerprint fails the run with
`storage_changed`; inspect the storage configuration instead of mixing datasets.
The current fingerprint uses native filesystem identities. Cross-host/restore
identity and non-Unix behavior still require qualification.

Completion is separate from health. The detail response reports enumeration,
supported layout, CAS assessment and reference-snapshot assessment separately.
Missing/corrupt bytes, unsupported entries, changes, limits and timeouts remain
findings. Staged and legacy files have no authoritative expected final digest;
they are counted as unverified and retained. `logical_file_bytes` is a decimal
string summing observed regular-file sizes by pathname. It is not allocated disk
space and can count hard-linked bytes more than once.

Read `/JOB_ID/observations` beneath the inventory path for immutable CAS receipts,
paged by generation using `after`. Read `/JOB_ID/references` for the original
reference snapshot and current-pass results, paged by ordinal. Reference receipt
history remains `/api/v1/jobs/JOB_ID/observations`. Every receipt identifies its
pass and target. A hash cannot approve quarantine or grant serving access.

POST `{}` with an idempotency key to `/api/v1/jobs/JOB_ID/cancel` or `/retry`.
Cancellation preserves committed pages and receipts; the in-flight generation
cannot advance after cancellation is accepted. Interrupted retries resume the
saved cursor. Completed retries recheck the same observed file set and original
reference snapshot in another pass. A new request performs a new walk. Old layout
findings remain part of their original walk after repair.

Operator controls:

| Control | Default and effect |
| --- | --- |
| `--inventory-entry-budget` | 1000000 retained directory entries per inventory |
| `--inventory-directory-entry-budget` | 1000000 entries read to compute one ordered directory page |
| `--integrity-sweep-target-budget` | 100000 reference-snapshot targets; oversized admission rolls back |
| Request `page_size` | 1–1000, within the directory budget; defaults to at most 100 |
| Worker integrity byte/rate/timeout settings | Apply to each CAS or reference check |

Pages retain bounded memory. Finding the next sorted page rescans its directory;
I/O work can grow faster than linearly for large directories. Existing SQL
deadlines and worker leases also apply. Exceeding a budget fails explicitly and
retains partial evidence without claiming completion. Limits are stored in the
run; after an operator adjustment, admit a new run. Production-scale/mixed-host
cost remains unqualified.

Descriptor-rooted publication and readback reject tenant/directory/object links
and special files. A named pipe cannot block the normal integrity-open path.
Worker credentials are checked again after metadata callbacks, and timed-out
attempts stop renewing their leases even if OS I/O stalls.

This is inventory and integrity evidence. Scheduling/sampling, supported repair,
holds/retention/GC, S3, consistent backup/restore, operator console and full
platform/scale qualification remain required.
