# Recover abandoned upload and source leases

Run the dedicated worker from [jobs.md](jobs.md). Its maintenance lane has one
reserved slot by default (`--maintenance-concurrency`). It uses the same tenant
credentials, forced RLS, durable attempt budgets and fenced job control as the
event and integrity lanes.

Preview a bounded sample with a tenant administrator credential:

```sh
bin/cratectl --token-file /private/path/admin.token --path '/api/v1/maintenance/reconciliations?repository=images&limit=100'
```

The response samples expired retrievals and upload sessions/operations separately
and reports `more`. This preview reserves nothing. A later execution takes its
own cutoff and checks every lease again. Omit `repository` to inspect this tenant.

POST `{"repository":"images","page_size":100}` to the same path with an
`Idempotency-Key` (8–128 characters). Omit the repository for the whole tenant;
page size defaults to 100 and must be 1–1000. The 202 response contains a `job`.
Read `/api/v1/jobs/JOB_ID` to inspect its state and `target` progress: cutoff,
phase, cursor, pages and the three recovery counters. Smaller pages reduce time
under the tenant write lock. Inspect a failed job before redriving it.

Each successful page commits its cursor with its effects and yields. A running
cancel request stops before the next page; already committed pages remain real.
Retry resumes the same cutoff and cursor. To cover leases that expired later,
create a new reconciliation with a new key. `bytes_deleted` is always zero.

A recovered retrieval becomes `failed` with `last_error=lease_recovered` and a new
generation. Its next authorized client request can fetch again. Recovery cannot
serve stale content or approve a policy decision. A recovered OCI operation keeps
its last acknowledged offset; read the native upload status before resuming.
An expired session returns 404, so begin another session. DELETE of the native
upload URL cancels an active session and fences its in-flight operation.

Server resource controls:

| Flag | Default and meaning |
| --- | --- |
| `--tenant-upload-concurrency` | 32 active sessions per tenant across nodes |
| `--upload-lease` | 30s renewable operation lease; 1s–5m |
| `--upload-ttl` | 30m rolling session lifetime; at least the lease, at most 24h |
| `--upload-part-budget` | 4096 nonempty immutable chunks, including an imported legacy prefix |
| `--upload-metadata-bytes` | 1 MiB, accounting 128 bytes per part |
| `--proxy-lease` | 150s renewable source lease; 1s–5m |
| `--max-object-bytes` | 1 GiB across the complete upload |

Heartbeats fail closed if credentials expire/revoke, repository grants change,
the database is unavailable or ownership changes. An unacknowledged chunk may
leave immutable bytes for future inventory; retries use the committed offset.
Legacy upload files are retained. Stop old registry processes before the current
development schema upgrade; production rolling migration is unqualified.

This operation does not inventory every object, remove orphan bytes, collect
garbage, enforce retention/holds or replace backup/restore. Those workflows remain
required before production readiness.
