# Recover missing or corrupt retained bytes

Use **Packages → Repair bytes** as a tenant administrator. Identify the exact
path and SHA-256, name the independently retained recovery copy and explain why
repair is needed. Preview reports the retained reference and the number of
bindings sharing those tenant-local bytes. Create the operation, choose its exact
source file and submit. The integrity worker must be running. The console shows
completion only after an immutable readback observation is recorded.

This operation supplies the exact bytes already named by retained metadata.
The complete SHA-256 and size must match. A matching hash establishes identity;
review, vulnerability assessment, holds and deletion state retain their existing
meaning. A repaired deleted artifact still requires explicit lifecycle restore.
Repair can help every repository reference to the same bytes in this tenant;
other tenants have separate storage namespaces. Conflicting retained sizes stop
the operation for metadata investigation.

You can close the dialog and resume a waiting operation from **Jobs → Inspect
job → Supply repair source**. A source upload that was not confirmed can be
retried with its original key and file. An accepted upload replay confirms the
original response; it does not inspect or replace another file sent on replay.
The console's transfer timeout is ten minutes. The server's request deadline also
applies and defaults to five minutes. Configure `cratectld serve --transfer-timeout
30m` or private runtime `transfer_timeout_seconds: 1800` for a longer transfer;
the bounded range is one second through 24 hours. Use the streaming CLI with an
explicit client timeout. Align the worker's `--job-timeout`, `--max-job-bytes` and
optional verification rate with the object size and required recovery time.

The API and CLI perform the same workflow:

1. Read `GET /api/v1/repositories/{name}/configuration` for the current
   `source_revision`. Read the retained artifact reference for its path/digest.
2. `POST /api/v1/repositories/{name}/artifacts/repairs` with a JSON plan containing
   `path`, `digest`, `expected_source_revision`, nonempty `reason` and `provenance`.
   Each text reason is bounded to 1024 UTF-8 bytes. `dry_run: true` previews without
   an operation. Apply requires an 8–128 character `Idempotency-Key` and returns
   `202`, the durable `job` ID and `state: awaiting_source`.
3. Supply exact bytes using a separate durable key:

   ```sh
   cratectl --config /private/client.json --method PUT \
     --path /api/v1/maintenance/repairs/JOB-ID/source \
     --upload-file /private/independent-copy.bin \
     --idempotency-key repair-source-unique-key --timeout 30m
   ```

   The endpoint accepts `application/octet-stream`. Declared length, if supplied,
   must match the plan. Source bytes are streamed and synced privately, then the
   accepted source and queued work commit together. Wrong bytes return
   `400 upload_mismatch`; no replacement occurs. A source filename never becomes
   a download URL. The requesting administrator credential must still be valid.
4. Read `GET /api/v1/jobs/JOB-ID` and its `/observations` page. A submitted source
   and an installation event are intermediate evidence. `succeeded` plus a
   `verified` immutable observation confirms readback. The job's public target
   omits requester credential hashes and local staging filenames.

The worker rechecks the requesting administrator, retained digest/size, source
revision, worker credential, cancellation and lease generation before installing.
Source hashing happens outside the tenant write transaction. Checked rooted
filesystem handles and a short fenced transaction protect installation. Healthy
objects retain their inode. Missing objects use create-only publication. Prior
corrupt regular files are retained before atomic replacement; this recovers bytes
without claiming reclaimed storage. Symlinks, special files and replaced storage
identities fail closed. The original source and corrupt files remain staged for
later supported retention handling.

A process or database failure can occur after filesystem installation and before
its database receipt. The durable job can then retry, check the actual current
bytes and record completion. A failed or cancelled job does not prove that an
already installed copy was undone. Inspect installation evidence and retry through
Jobs after resolving the classified error. Source/configuration changes or an
expired/revoked requester require a new authorized plan. A completely missing
tenant directory can be initialized while staging; if an invalid first source
changes that empty layout, preview a new plan against its current identity.

Upgrade with registry and workers stopped. Schema 5 preserves receipts 1–4 and
adds the repair-capable runtime admission receipt, so old workers cannot claim
unknown repair jobs. This is controlled maintenance; rolling worker compatibility
is not established. Native Windows filesystem replacement, S3 repair, legacy
format metadata repair, automatic upstream repair, scheduling, retention/GC,
large-scale recovery and complete backup/restore remain required work.
