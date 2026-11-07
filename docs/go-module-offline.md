# Prepare a hosted Go package for a disconnected client

`go-module-offline` prepares one exact hosted module/version as a private file
GOPROXY. Its original publication mode is qualified on both native GitHub Linux
architectures at1a61120:81named Go PostgreSQL functions normally/race and312stock
checks. Both original d179222 cache-cleanup failures and skipped stages remain
retained; the exact fixture repair replays with standard SDK read-only cache
behavior. The new schema15 producer and manifest mode below remain native
unverified. See ADR0050 and the source-specific native checkpoint.

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
registry. The new single-version durable producer is implemented but native unverified;
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
import, background expiry maintenance, physical GC, provider/independent-host/
Windows/scale and backup outcomes remain open in the export acceptance plan.
