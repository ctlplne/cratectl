# Prepare a hosted Go package for a disconnected client

`go-module-offline` prepares one exact hosted module/version as a private file
GOPROXY. It is implemented but native unverified. Local ARM checks pass. The
first d179222 attempt fails native fixture cleanup on both Linux
hosts after Go creates its standard read-only module cache. DEFECT0128 uses the
pinned SDK cleaner for only that fresh test cache; native replay is required.
Original race/stock stages skipped and are not passes. The original failures
are retained in `evidence/2026-11-07/go-hosted-offline-d179222-first-failure.json`.

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
registry. Full server export sessions and policy/proof/dependency bundles remain
open in [ADR0049](adr/0049-hosted-go-offline-publication.md).

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
