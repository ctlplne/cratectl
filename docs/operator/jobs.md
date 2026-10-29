# Durable jobs and storage integrity

Run a worker alongside the registry against the same runtime PostgreSQL database
and durable object directory. No vendor account or owner database connection is
needed by the worker. Stop workers before applying this development migration;
it preserves existing event jobs while extending their key for multiple effects.
Production rolling migration and restore qualification remain open.

Use the owner connection only to migrate and provision a separate credential:

```sh
bin/cratectld migrate
bin/cratectld provision --tenant example --actor storage-worker --role worker \
  --token-file /private/path/example-worker.token
```

Create an owner-readable-only JSON file, such as `/private/path/workers.json`:

```json
{"token_files":["/private/path/example-worker.token"]}
```

Keep that file and every token at mode 0600. Token values stay in token files.
Give each configured tenant one worker identity; duplicates are rejected so an
extra credential cannot silently give a tenant extra scheduling weight. The
configuration byte budget is adjustable. Worker credentials are rejected by the
public artifact/management API; public admin tokens are rejected by the worker.

```sh
bin/cratectld worker --identities /private/path/workers.json \
  --objects /durable/cratectl/objects --name cratectl-worker-one
```

Set `CRATECTL_DSN` to the nonowner runtime connection and remove
`CRATECTL_OWNER_DSN` from the worker environment. Each operation rechecks current
expiry and revocation after acquiring the database lock. To rotate, provision a
replacement, update the private configuration and restart the worker. Revoking
one tenant's credential stops its effects while other configured tenants proceed.

The worker implements three lanes:

| Lane / handler | Observed effect |
| --- | --- |
| `events` / `event.project` | Verify a source journal event and publish its activity index entry |
| `integrity` / `storage.integrity` | Hash a publication repository/digest/size binding and retain an attempt observation |
| `integrity` / `storage.sweep` | Inspect every target of an admitted referenced-storage snapshot, with durable coverage and per-pass receipts |
| `maintenance` / `leases.reconcile` | Recover bounded pages of expired retrieval/upload lease metadata, retaining bytes and offsets |

An event job's `kind` names its source event; `handler` names the effect actually
performed. A successful hash means the observed stored bytes matched their
declared SHA-256 and length. It does not assess malware, vulnerabilities,
signatures or licensing, and never approves quarantine. Current policy and the
serving integrity check still govern every download.

Publication writes job intent with its references and journal event. Alias
bindings within one mutation share a byte check. Jobs and their IDs are scoped
to the authenticated tenant; equal IDs can exist in different tenants. A path is
the original display coordinate. The check binds immutable bytes, so a retargeted
coordinate cannot transfer an old observation to its new digest.

Publication tasks cover new publication/cache-fill intent and explicit redrives.
Administrators can also request a [referenced-storage integrity sweep](integrity-sweeps.md)
of pre-existing artifact/upload-part bindings. Full CAS/staged/orphan inventory
remains required; starting a worker alone does not imply any sweep was scheduled.

Inspect queues and jobs using a tenant administrator credential:

```sh
bin/cratectl --token-file /private/path/admin.token --path /api/v1/jobs/queues
bin/cratectl --token-file /private/path/admin.token --path '/api/v1/jobs?queue=integrity&state=failed&limit=100'
bin/cratectl --token-file /private/path/admin.token --path '/api/v1/jobs/JOB_ID/observations'
```

Use `limit` 1–1000 and follow `next` for job inventory. That cursor enumerates the
current inventory; refresh or read a job directly to watch changing states.
Observations page by generation using `after`. Activity pages use the returned
last item's `position`, not its source `sequence`, as `after`. This preserves
late completions from slower workers. Full audit remains `/api/v1/audit`.

Queue policies default to capacity 100000, running limit 2, five attempts and
exponential retry from five to 300 seconds. Administrators can change each lane's
resource budgets with an idempotent PUT to `/api/v1/jobs/queues/QUEUE`. Send only
configuration fields:

```json
{"capacity":100000,"max_running":2,"max_attempts":5,"retry_seconds":5,"retry_max_seconds":300}
```

Capacity may be reduced below existing outstanding work; it preserves that work
and rejects new admission until the backlog drains. A 503 `durable_queue_full`
means the attempted publication rolled back. Start/repair workers, inspect
failed work or adjust capacity. Increasing policy budgets, cancelling work and
emergency credential operations remain possible while the outbox is full.
An affected proxy fill releases its own fence and can retry immediately after
capacity repair. Orphan staged bytes are retained; no cleanup is inferred.

| State | Meaning and next action |
| --- | --- |
| `pending` | Admitted work awaiting a claim |
| `running` | A live generation owns a renewable lease |
| `retry` | A failed attempt waits for durable backoff |
| `succeeded` | The named handler's effect committed; inspect its assessment scope |
| `failed` | Budget exhausted or permanent input/resource failure; inspect and repair before retry |
| `cancel_requested` | Stop requested; work has not yet acknowledged stopping |
| `cancelled` | Acknowledged or recovered cancellation; no success observation from that attempt |
| `uncertain` | Reserved for future external adapters with unknown remote outcome; these builtins do not produce it |

POST `{}` to `/api/v1/jobs/JOB_ID/retry` or `/cancel`, with an
`Idempotency-Key`. A retry preserves total attempts and prior observations while
resetting the attempt cycle. Replaying that key returns the original response,
even if the job has since progressed. A succeeded job can be explicitly redriven
for a new observation; successful effects cannot be retrospectively cancelled.
An uncertain future external effect requires `{"acknowledge_unknown":true}` to
retry after the operator reconciles the remote outcome.

Hard process death leaves a lease for later reclaim. The next generation fences
the old owner; an expired heartbeat cannot resurrect it. Cancellation is checked
by heartbeat and before committing the effect. Graceful shutdown may leave an
unfinished lease, and a lost completion acknowledgment requires reading job state
instead of assuming success. The builtin database effect and job transition are
one transaction. External exactly-once effects are not claimed.

| Worker flag | Default | Bound / purpose |
| --- | --- | --- |
| `--event-concurrency` | 1 | Reserved projection slots, 1–256 |
| `--integrity-concurrency` | 1 | Reserved byte-check slots, 1–256 |
| `--lease` | 30s | Renewable fence, 1s–5m |
| `--poll` | 250ms | Idle polling, 10ms–1m |
| `--job-timeout` | 2m | One attempt, 1s–24h |
| `--max-job-bytes` | 1 GiB | Maximum declared object bytes |
| `--max-event-bytes` | 16 MiB | Bounded projection input, at most 1 GiB |
| `--verify-bytes-per-second` | 16 MiB | Pacing per integrity slot; 0 disables pacing |
| `--identity-config-bytes` | 1 MiB | Adjustable private configuration memory bound, at most 1 GiB |

Round robin applies across configured tenants within each separately reserved
lane. Persisted lane concurrency applies across processes. Deadlines and I/O
pacing bound a large hash's interference, but broader distributed fairness and
scale remain unqualified. Terminal history is retained; job history retention,
S3, scanners, external deliveries, orphan/retrieval/upload reapers, GC and full
restore/upgrade/security qualification remain required.

Run the owned native proof after building the clean committed source and starting
the development database:

```sh
CRATECTL_DEV_DATABASE=native python3 scripts/dev.py python3 scripts/conformance_jobs.py --require-clean-build
```

It uses the reserved registry port, two fresh tenants and their own shared local
CAS. It kills only its worker, injects corruption only into its own retained
fixture object, repairs those exact bytes and stops its own processes. Credentials
and private logs remain under `.private/jobs-conformance/`; evidence records
source/binary identity and assertions without credential values.

The independent maintenance lane executes bounded expired retrieval/upload lease
reconciliation. See [recovery.md](recovery.md) for preview, admission, progress,
cancellation, retry and the byte-retention contract. CAS inventory and GC remain
required; starting a worker does not automatically schedule a maintenance scan.
