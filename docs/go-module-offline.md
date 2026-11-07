# Prepare a hosted Go package for a disconnected client

`go-module-offline` prepares one exact hosted module/version as a private file
GOPROXY. Its original publication mode is qualified on both native GitHub Linux
architectures at1a61120:81named Go PostgreSQL functions normally/race and312stock
checks. Both original d179222 cache-cleanup failures and skipped stages remain
retained; the exact fixture repair replays with standard SDK read-only cache
behavior. At exact `15a49d3`, the schema-15 producer and manifest mode pass 93
named PostgreSQL functions normally/under race on both Linux architectures. The
separate x86-producer/ARM-consumer profile passes all 16 stages. Schema-16 indexed
expiry is implemented and awaiting its own complete native qualification. See
[ADR0050](adr/0050-durable-hosted-go-export.md) and the source-specific checkpoints.

You need the original ZIP, `go.mod` and `.info` bytes, the exact original
`go.module.published` event sequence, a complete journal containing that event,
and a checkpoint signed outside cratectl with an independently trusted public
key. Collect package bytes through the ordinary authorized Go routes and use
[journal export](journal-export.md) for the immutable range and external signing
steps. Keep private files under an owner-private directory with `umask 077`.

The journal signer authenticates historical publication. Approve these exact
packages for your disconnected environment first. This command cannot determine
current server permissions, scan approval, revoked/latest history or whether you
have every dependency. It does not supply a SumDB approval or import into a live
registry. The single-version durable producer has named source-15 native proof;
complete policy/proof/permission/dependency bundles remain open in
[ADR0050](adr/0050-durable-hosted-go-export.md).

For example, after independently selecting the exact original event and signed
terminal checkpoint:

```sh
cratectl go-module-offline \
  --repository hosted \
  --module go.cratectl.invalid/Owned/offline --version v1.0.0 \
  --zip-file /private/path/original.zip \
  --mod-file /private/path/original.mod \
  --info-file /private/path/original.info \
  --output-directory /private/path/offline-output \
  --journal-file /private/path/journal.jsonl \
  --journal-tenant "$CRATECTL_TRUSTED_TENANT" \
  --journal-event-sequence "$CRATECTL_PUBLICATION_SEQUENCE" \
  --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --checkpoint-file /private/path/checkpoint.json \
  --checkpoint-signature-file /private/path/checkpoint.sig \
  --checkpoint-key-file /private/path/independently-trusted-public.pem
```

The output directory must not exist; its parent must already be private. Input
files must be private regular files, not symlinks or pipes. Original bytes are
copied and hashed before the copied ZIP/metadata is parsed. Linux/macOS are
supported by this implementation; Windows private ACL/durability is unsupported.
Limits are512MiB ZIP,512MiB expansion,1MiB go.mod,64KiB info,16MiB ZIP directory
and16384entries. Byte work defaults to5minutes (`--timeout`, positive through1h);
the independent complete-journal budget uses `--journal-timeout` and
`--journal-max-bytes`. No output proxy is accepted from a valid journal prefix.

After success, `receipt.json` records the journal/signature proof, original
digests, computed h1 values and `goproxy` URL. Its current-admission and checksum-
authority fields are false. The native proxy is `offline-output/proxy`, which
contains the original Go URL-escaped module paths and the three unchanged files.
Use the exact returned file URL as the only GOPROXY, with no `direct` fallback:

```sh
GOENV=off GOWORK=off GOTOOLCHAIN=local GOAUTH=off \
  GOPROXY=file:///private/path/offline-output/proxy \
  GOSUMDB=off GONOSUMDB='*' GONOPROXY=none GOVCS='*:off' \
  go mod download -json go.cratectl.invalid/Owned/offline@v1.0.0
```

This explicit private-hosted trust choice uses the authenticated historical
publication instead of a network checksum service. It does not repair the
separate strict Go client trust-state failure. The command itself never runs
the SDK, extracts/builds code, fetches a dependency, signs data or reads a signing
private key. Missing dependencies fail against the sole file proxy; complete
closure and multi-package exports remain required work.

## Collect a durable export snapshot

An administrator can now preview and create one hosted version through
`POST /api/v1/go/exports/preview` and `POST /api/v1/go/exports`. Both take a
4096-byte JSON object containing `repository`, `module`, `version`,
`expected_source_revision` and `lifetime_seconds` (60–3600). Creation requires a
nonempty Idempotency-Key. The Exports console provides this path and private
collection commands; the standard management CLI supports the same requests.
Creation verifies original physical bytes, stages/syncs the canonical manifest,
then rechecks exact source/policy/byte state before committing session, item
references, event, receipt and job together. A preview's hash remains unsigned.

Read `GET /api/v1/go/exports/ID` before resuming. Download `manifest`, `zip`, `mod`
and `info` at `/api/v1/go/exports/ID/KIND?generation=GENERATION`. Each request
checks current source, all bundle policy, generation and expiry. One bounded
HTTP Range and ordinary conditional requests are supported. Hash and verify the
complete copied bytes before accepting them. A transfer is bounded to90seconds;
interrupted large transfers need a current-generation range request. Keep files
private and use fresh output paths; preserve incomplete files as diagnostics.

Renew, acknowledge, cancel or reconcile expiry with `PATCH /api/v1/go/exports/ID`
and a new Idempotency-Key. Supply all four fields: `action`,
`expected_generation`, `lifetime_seconds`, `manifest_sha256`. Renew takes60–3600
seconds and stays within the original24hours; other actions use zero seconds.
Each transition changes generation. Acknowledgment records your statement with
`delivery_verified=false`. Expiry blocks serving and retains pins until its
terminal transaction commits. Queue failure preserves protection. Cancellation
or durable expiry releases package pins and retains the historical manifest.
The operator controls retained-session capacity with `--export-session-limit`.
This adds no physical-GC deletion permission.

The normal `cratectld worker` process also expires due sessions for its configured
tenants. It needs a current dedicated worker credential; no administrator read
or source access is required. It processes at most one due session per tenant
visit, paced by at least one second, and records expiry and projection intent
atomically. Queue or credential failure keeps payload pins retained and emits a
bounded `go_export_expiry_*` notice. Renewals and other workers share the same
database fence. The historical manifest remains retained. This worker path is
implemented but still requires its new native PostgreSQL qualification.

For independent offline verification, collect a complete journal that includes
this session's **created_sequence**. Authenticate its terminal checkpoint through
your external signer and separately trusted public key as described above.
Add both flags to the existing `go-module-offline` invocation:

```sh
  --export-id EXACT_SESSION_ID \
  --manifest-file /private/path/downloaded-manifest.json
```

Set `--journal-event-sequence` to the export's original `created_sequence`.
The command verifies the complete signed range, original `go.export.created`
event and exact canonical manifest identity before using its three digests.
It preserves that original manifest as `export-manifest.json` next to the new
file GOPROXY. The receipt identifies the export and manifest; source policy is
historical context and does not approve the destination or supply SumDB trust.

This profile still exports one hosted version. Complete dependency closure,
source permission/authority/provenance bundles, destination current-policy
import, large-backlog expiry throughput, physical GC, provider/independent-host/
Windows/scale and backup outcomes remain open in the export acceptance plan.

The new cross-runner qualification workflow prepares the owned signed fixture on
an x86 GitHub VM and verifies/consumes it on a separate native ARM VM. After
online transfer, the consumer uses fresh empty network namespaces for the CLI
and stock Go commands. Its public key is checked against a separate source-job
fingerprint before verification. The fixture capsule is only CI test data;
normal customer collection still uses the documented API and private files.
The exact source `15a49d3` passed both actual GitHub jobs and all 16 stages. See
[ADR0052](adr/0052-cross-runner-go-export-qualification.md) and the
[named checkpoint](../evidence/2026-11-07/go-export-portability-15a49d3-checkpoint.json).
This verifies one owned hosted version; it does not complete dependency closure,
destination import or a customer-selected trust-provider integration.

Source16 named95Go normal/race and both historical upgrade profiles now pass at470ca74. The whole campaign remains unaccepted because of the separate ARM Ant/Ivy bootstrap failure.

Schema 16 adds an ordered partial index so an idle expiry worker reads only the
earliest nonterminal session. It requires stopped-registry migration and matching
binaries; its named native proof is retained at470ca74; broad operations/clock/scale qualification remains incomplete. Existing schema-15 receipts,
manifest/package bytes, deadlines and payload roots must survive unchanged. The
primary schema-11 environment has not been migrated or switched. See
[ADR0053](adr/0053-indexed-export-expiry.md).

## Resume collection through the CLI

`cratectl go-export-collect` collects one durable hosted export plus its complete
signed journal, checkpoint, signature and public key into a private directory.
The new command is implemented; its new native process-interruption journey must
still pass on the exact source. See [ADR0055](adr/0055-resumable-signed-go-collection.md).
The previously qualified API/offline commands do not by themselves qualify this
collector.

First obtain the complete journal and externally signed checkpoint using the
[journal workflow](journal-export.md). Independently select the tenant, terminal
sequence/hash, signer public key and the original export-created event. Read the
current session for its exact serving generation. Then collect:

```sh
umask 077
mkdir -m 700 ./cratectl-export-input
cratectl go-export-collect \
  --config "$CRATECTL_CLIENT_CONFIG" \
  --export-id "$CRATECTL_EXPORT_ID" --generation "$CRATECTL_EXPORT_GENERATION" \
  --repository hosted --module go.cratectl.invalid/Owned/offline --version v1.0.0 \
  --output-directory ./cratectl-export-input/collected \
  --journal-file ./cratectl-journal.jsonl \
  --journal-tenant "$CRATECTL_TRUSTED_TENANT" \
  --journal-event-sequence "$CRATECTL_EXPORT_CREATED_SEQUENCE" \
  --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --checkpoint-file ./checkpoint.json --checkpoint-signature-file ./checkpoint.sig \
  --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
```

If collection stops, preserve the directory. Inspect current access, policy,
network/TLS and session state. Rerun only the collector command with `--resume`,
the same signed inputs and directory. If you renewed the session, explicitly
supply its new generation. A changed authority, export, manifest or proof refuses
resume. The collector never truncates a bad prefix or replaces a corrupt receipt;
preserve those files and choose a fresh directory when their identities differ.
Completed receipt replay rehashes the files and rechecks current serving access,
then returns the original receipt bytes. It does not renew or acknowledge the
session. Current denial/revocation prevents a new successful collector response;
already collected bytes and historical receipts remain local.

The directory contains `manifest.json`, `original.zip`, `original.mod`,
`original.info`, `journal.jsonl`, `checkpoint.json`, `checkpoint.sig`,
`signer-public.pem`, immutable `bindings.json` and a final `receipt.json`.
Credentials, client configuration and signing private keys are excluded. Until a
complete receipt verifies, files may be partial. The receipt proves collected
historical bytes; current registry/destination admission, checksum authority,
dependency closure and remote delivery acknowledgment remain false.

Requests are serial, refuse redirects/compressed responses, and use exact
HTTP ranges, digests and generation headers. `--chunk-bytes` defaults to 4 MiB
(64 KiB–8 MiB); files are synced at checkpoints. Combined retained bytes default
to 2 GiB with `--max-bytes` (at most 65 GiB, still subject to every smaller
manifest/journal/format limit). `--timeout` bounds the collection phase to five
minutes by default, at most one hour. Independent journal verification keeps its
existing `--journal-timeout` and `--journal-max-bytes` budgets. Response headers
are capped at 32 KiB; each request has a one-minute deadline. These are resource
bounds, not license limits.

Use the copied journal/checkpoint/signature and three original representations
with `go-module-offline`. Keep `--checkpoint-key-file` pointed at your separately
trusted original key or authenticate the copied key's identity independently;
an adjacent `signer-public.pem` is not its own trust source. The console provides
first-collection and resume commands with the selected exact session generation.
Its browser checks are UI response stand-ins, distinct from native collector
and stock-client evidence. Linux/macOS private files and directory locks are the
implemented path; Windows ACL/durability qualification and complete disconnected
closure, installation, provider integration and destination import remain open.

Collection metadata is staged separately before final publication. During an
interruption you may see `.bindings.pending` or `receipt.GENERATION.pending`.
Leave these files in place and use `--resume`: the collector can finish an exact
prefix and recover its own published alias. If serving was renewed, the final
receipt preserves the earlier completion generation after rechecking current
access and all bytes. Corrupt completed metadata, unrelated links and ambiguous
pending states are preserved and refused. A successful directory still contains
the ten documented files. The implemented local filesystem path requires atomic
hard links, directory sync and locking; unsupported filesystem behavior fails
without replacing an existing final record. See
[ADR0056](adr/0056-atomic-collection-metadata.md) for the qualification limits.

## Publish verified historical bytes at a destination

`cratectl go-export-import` is implemented; exact-source native qualification is
pending. It verifies the same complete signed export and prepares private copies
before contacting the destination. It publishes one exact hosted version through
normal destination permissions and policy. It does not approve it for serving.
See [ADR0057](adr/0057-signed-export-destination-publication.md).

Using the trusted identities selected for collection above:

```sh
cratectl go-export-import \
  --config "$CRATECTL_DESTINATION_CLIENT_CONFIG" \
  --destination-repository imported \
  --repository hosted --module go.cratectl.invalid/Owned/offline --version v1.0.0 \
  --export-id "$CRATECTL_EXPORT_ID" \
  --manifest-file ./cratectl-export-input/collected/manifest.json \
  --zip-file ./cratectl-export-input/collected/original.zip \
  --mod-file ./cratectl-export-input/collected/original.mod \
  --info-file ./cratectl-export-input/collected/original.info \
  --output-directory ./cratectl-export-input/import-attempt-001 \
  --idempotency-key "$CRATECTL_DESTINATION_IMPORT_KEY" \
  --journal-file ./cratectl-export-input/collected/journal.jsonl \
  --journal-tenant "$CRATECTL_TRUSTED_TENANT" \
  --journal-event-sequence "$CRATECTL_EXPORT_CREATED_SEQUENCE" \
  --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --checkpoint-file ./cratectl-export-input/collected/checkpoint.json \
  --checkpoint-signature-file ./cratectl-export-input/collected/checkpoint.sig \
  --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
```

Keep the same nonempty mutation key for identical retries. A failed response may
follow a committed publication: preserve the attempt directory, inspect current
destination access/state, then repeat explicitly with the same inputs/key and a
new private output directory. The tool never retries automatically. Its synced
`import-intent.json` precedes the request; `import-receipt.json` exists only after
an exact canonical destination publication response. No client configuration or
token is copied. The attempt also retains the verified source proxy and manifest.

Destination scan evidence remains unassessed when absent. Source approval never
grants destination approval; a review-required destination continues to refuse
serving until its own current policy is satisfied. The receipt's current admission,
checksum authority and dependency closure fields remain false. This path accepts
only exact normal hosted info bytes; unsupported original metadata is preserved
and refused before upload. Full import/provenance/scan workflows, console progress,
transitive closure and Windows/provider/backup/scale qualification remain open.
