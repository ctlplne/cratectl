# Export and verify a bounded journal range

Implementation status: ARM development build/unit/race/lint, parser fuzz and
reproducible console checks pass. New real-PostgreSQL tests compile normally and
under race and pass tagged vet only; actual native PostgreSQL, CLI and browser
qualification is pending. This document does not declare release readiness.

The tenant journal retains original event payloads. Each event hash covers the
previous hash, one newline and the exact original payload bytes. The new export
path verifies every consecutive sequence, tenant binding and hash link through
an exact terminal checkpoint. It does not reconstruct old payloads from current
database state.

A hash returned beside its data cannot authenticate itself. Before attributing
an export to cratectl, obtain the exact tenant, terminal sequence and terminal
SHA-256 through a separate trusted record or your existing external signing
tool. Verify that external record using independently configured trust. The
server checkpoint endpoint is explicitly unsigned. External signing/provider
adapters remain required work; cratectl does not run a signing or key-custody
service.

## Observe and authenticate a checkpoint

Use a current tenant administrator credential and the private client JSON from
installation. This read returns an observation, not independent trust:

```sh
umask 077
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path /api/v1/audit/checkpoint --raw-response > unsigned-checkpoint.json
```

The response contains `checkpoint: {tenant, sequence, hash}`, `signed: false`
and trust instructions. Genesis is sequence zero with an empty hash. Preserve
the exact observation and authenticate it outside the downloaded evidence.
Do not silently replace a previously authenticated checkpoint when a different
server hash appears.

After checking that separate trust path, set these environment variables from
the authenticated record. They are ordinary checkpoint values, not credentials:

```sh
export CRATECTL_TRUSTED_TENANT=your-tenant
export CRATECTL_TRUSTED_JOURNAL_SEQUENCE=123
export CRATECTL_TRUSTED_JOURNAL_HASH=the-exact-64-character-lowercase-sha256
```

The example values are placeholders. Sequence and hash must come from the
same record and tenant. Empty hash is accepted only for sequence zero.

## Collect a fixed range

```sh
umask 077
cratectl journal-export --config "$CRATECTL_CLIENT_CONFIG" \
  --tenant "$CRATECTL_TRUSTED_TENANT" \
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --output ./cratectl-journal.jsonl
```

Collection starts at genesis by default. It uses the configured CA, verifies TLS,
refuses redirects and allows cleartext HTTP only to a literal loopback address.
Every request requires current administrator authority. A revoked or expired
credential cannot reread an old export page. The client follows only verified
advancing cursors while retaining the same terminal sequence/hash. Later journal
appends cannot move that range boundary.

The output file must be new; an existing file or symlink is never replaced. It is
created with mode 0600. Each page is verified before retention. The client syncs
the file and streams the complete saved bytes through the offline verifier,
including EOF, before emitting a success receipt. A failed collection leaves an
incomplete private file and returns nonzero without a success receipt. Preserve
that file and investigate. To retry, choose a new output path and retain the
same independently authenticated bindings.

For an incremental range, also supply `--after` and `--after-hash` from a
separately trusted prior checkpoint. The selected events are strictly after
that sequence and through the terminal sequence, inclusive. An identical
start/head produces one empty range page. Genesis exports use explicit
`--through 0 --through-hash ''`.

## Verify independently while offline

Copy the private file and independently authenticated checkpoint to the
verification machine. No server, database, credential, signer or network is
needed:

```sh
cratectl journal-verify --export-file ./cratectl-journal.jsonl \
  --tenant "$CRATECTL_TRUSTED_TENANT" \
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH"
```

Use matching `--after`/`--after-hash` for an incremental export. The receipt names
the tenant, start/head bindings, page/event counts, exact input-file SHA-256 and
`matches_supplied_checkpoint`. This means the entire supplied range matches
the provided checkpoint. Attribution depends on the checkpoint's separate trust
path. Event integrity does not prove arbitrary event claims, external delivery,
security cleanliness or package admission.

Empty input, a missing terminal page/newline, repeated/reordered/trailing pages,
wrong tenant/anchors, changed payloads, sequence gaps, unknown/duplicate wire
fields and exhausted budgets fail without a success receipt. No valid prefix
is treated as a complete export. Journal page records are canonical version-1
JSON followed by LF. Preserve exact response bytes. One optional blank line
between records is accepted for the generic management CLI's terminal newline;
pretty-printing or normalizing JSON is not accepted.

## Bounds and failure handling

- API pages contain at most 1,000 events and 2 MiB including framing. Original
  event payloads may contain at most 256 KiB. PostgreSQL first returns bounded
  size/hash metadata; only selected payloads cross the database connection.
- The API may shorten a page before reaching its event-count limit. Follow
  `more`, `next_after` and `next_hash`, rather than inferring completion from a
  short page. The older `/api/v1/audit` list now also returns `more/next_after`
  with equivalent byte bounds. Its moving observation remains a live list.
- Both commands default to a 1 GiB file budget and five-minute total timeout.
  `--max-bytes` may be 1–64 GiB; `--timeout` may be positive through one hour.
  Collection uses one request at a time, a one-minute per-request timeout and
  at most 65,536 page records. The offline verifier separately bounds frames,
  individual events, parser allocation and total input bytes.
- `journal_checkpoint_changed` (409) means a supplied anchor is absent or
  differs from retained history. Preserve the trusted checkpoint and original
  evidence; a newly fetched hash cannot authorize replacement trust.
- `journal_evidence_limit` or `journal_evidence_unavailable` (503) means this
  retained range exceeds the supported profile or fails original integrity
  checks. Unsupported large events are not skipped or called clean. A
  separately qualified large-event recovery path remains required.

In the console, **Audit → Complete journal export** explains unsigned trust and
provides commands that require separate checkpoint variables. Values outside
exact browser integer precision disable copy actions; use exact API/CLI values.
**Export this page · JSON** remains a scoped view download, not a full verified
journal. Protect downloaded audit data as private tenant evidence.

This foundation does not finish signed export manifests/adapters, Go package and
proof bundles, backup/restore, export/GC protection leases, offline cache/install,
large-history performance, all browsers/platforms or the remaining GOAL scope.
The independently reproduced Go client trust-state failure (DEFECT.0126) remains
open and separate from journal verification.
